# SPDX-FileCopyrightText: 2014-2022 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import hashlib
import io
import os
import struct
import sys
import time
import zlib
import itertools

from .bin_image import LoadFirmwareImage
from .loader import (
    DEFAULT_CONNECT_ATTEMPTS,
    DEFAULT_TIMEOUT,
    ERASE_WRITE_TIMEOUT_PER_MB,
    ESPLoader,
    timeout_per_mb,
)
from .targets import ROM_LIST
from .util import (
    FatalError,
    NotImplementedInROMError,
    UnsupportedCommandError,
)
from .util import (
    div_roundup,
    flash_size_bytes,
    hexify,
    pad_to,
    print_overwrite,
)

DETECTED_FLASH_SIZES = {
    0x12: "256KB",
    0x13: "512KB",
    0x14: "1MB",
    0x15: "2MB",
    0x16: "4MB",
    0x17: "8MB",
    0x18: "16MB",
    0x19: "32MB",
    0x1A: "64MB",
    0x1B: "128MB",
    0x1C: "256MB",
    0x20: "64MB",
    0x21: "128MB",
    0x22: "256MB",
    0x32: "256KB",
    0x33: "512KB",
    0x34: "1MB",
    0x35: "2MB",
    0x36: "4MB",
    0x37: "8MB",
    0x38: "16MB",
    0x39: "32MB",
    0x3A: "64MB",
}

FLASH_MODES = {"qio": 0, "qout": 1, "dio": 2, "dout": 3}


def detect_chip(
    port=ESPLoader.DEFAULT_PORT,
    baud=ESPLoader.ESP_ROM_BAUD,
    connect_mode="default_reset",
    trace_enabled=False,
    connect_attempts=DEFAULT_CONNECT_ATTEMPTS,
):
    """Use serial access to detect the chip type.

    First, get_security_info command is sent to detect the ID of the chip
    (supported only by ESP32-C3 and later, works even in the Secure Download Mode).
    If this fails, we reconnect and fall-back to reading the magic number.
    It's mapped at a specific ROM address and has a different value on each chip model.
    This way we use one memory read and compare it to the magic number for each chip.

    This routine automatically performs ESPLoader.connect() (passing
    connect_mode parameter) as part of querying the chip.
    """
    inst = None
    detect_port = ESPLoader(port, baud, trace_enabled=trace_enabled)
    if detect_port.serial_port.startswith("rfc2217:"):
        detect_port.USES_RFC2217 = True
    detect_port.connect(connect_mode, connect_attempts, detecting=True)
    try:
        print("Detecting chip type...", end="")
        chip_id = detect_port.get_chip_id()
        for cls in [
            n for n in ROM_LIST if n.CHIP_NAME not in ("ESP8266", "ESP32", "ESP32-S2")
        ]:
            # cmd not supported on ESP8266 and ESP32 + ESP32-S2 doesn't return chip_id
            if chip_id == cls.IMAGE_CHIP_ID:
                inst = cls(detect_port._port, baud, trace_enabled=trace_enabled)
                try:
                    inst.read_reg(
                        ESPLoader.CHIP_DETECT_MAGIC_REG_ADDR
                    )  # Dummy read to check Secure Download mode
                except UnsupportedCommandError:
                    inst.secure_download_mode = True
                inst._post_connect()
                break
        else:
            err_msg = f"Unexpected chip ID value {chip_id}."
    except (UnsupportedCommandError, struct.error, FatalError) as e:
        # UnsupportedCommandError: ESP8266/ESP32 ROM
        # struct.error: ESP32-S2
        # FatalError: ESP8266/ESP32 STUB
        print(" Unsupported detection protocol, switching and trying again...")
        try:
            # ESP32/ESP8266 are reset after an unsupported command, need to reconnect
            # (not needed on ESP32-S2)
            if not isinstance(e, struct.error):
                detect_port.connect(
                    connect_mode, connect_attempts, detecting=True, warnings=False
                )
            print("Detecting chip type...", end="")
            sys.stdout.flush()
            chip_magic_value = detect_port.read_reg(
                ESPLoader.CHIP_DETECT_MAGIC_REG_ADDR
            )

            for cls in ROM_LIST:
                if chip_magic_value in cls.CHIP_DETECT_MAGIC_VALUE:
                    inst = cls(detect_port._port, baud, trace_enabled=trace_enabled)
                    inst._post_connect()
                    inst.check_chip_id()
                    break
            else:
                err_msg = f"Unexpected chip magic value {chip_magic_value:#010x}."
        except UnsupportedCommandError:
            raise FatalError(
                "Unsupported Command Error received. "
                "Probably this means Secure Download Mode is enabled, "
                "autodetection will not work. Need to manually specify the chip."
            )
    finally:
        if inst is not None:
            print(" %s" % inst.CHIP_NAME, end="")
            if detect_port.sync_stub_detected:
                inst = inst.STUB_CLASS(inst)
                inst.sync_stub_detected = True
            print("")  # end line
            return inst
    raise FatalError(
        f"{err_msg} Failed to autodetect chip type."
        "\nProbably it is unsupported by this version of esptool."
    )


# "Operation" commands, executable at command line. One function each
#
# Each function takes either two args (<ESPLoader instance>, <args>) or a single <args>
# argument.


def detect_flash_size(esp, args=None):
    # TODO: Remove the dependency on args in the next major release (v5.0)
    if esp.secure_download_mode:
        if args is not None and args.flash_size == "detect":
            raise FatalError(
                "Detecting flash size is not supported in secure download mode. "
                "Need to manually specify flash size."
            )
        else:
            return None
    flash_id = esp.flash_id()
    size_id = flash_id >> 16
    flash_size = DETECTED_FLASH_SIZES.get(size_id)
    if args is not None and args.flash_size == "detect":
        if flash_size is None:
            flash_size = "4MB"
            print(
                "WARNING: Could not auto-detect Flash size "
                f"(FlashID={flash_id:#x}, SizeID={size_id:#x}), defaulting to 4MB"
            )
        else:
            print("Auto-detected Flash size:", flash_size)
        args.flash_size = flash_size
    return flash_size


def _update_image_flash_params(esp, address, args, image):
    """
    Modify the flash mode & size bytes if this looks like an executable bootloader image
    """
    if len(image) < 8:
        return image  # not long enough to be a bootloader image

    # unpack the (potential) image header
    magic, _, flash_mode, flash_size_freq = struct.unpack("BBBB", image[:4])
    if address != esp.BOOTLOADER_FLASH_OFFSET:
        return image  # not flashing bootloader offset, so don't modify this

    if (args.flash_mode, args.flash_freq, args.flash_size) == ("keep",) * 3:
        return image  # all settings are 'keep', not modifying anything

    # easy check if this is an image: does it start with a magic byte?
    if magic != esp.ESP_IMAGE_MAGIC:
        print(
            "Warning: Image file at 0x%x doesn't look like an image file, "
            "so not changing any flash settings." % address
        )
        return image

    # make sure this really is an image, and not just data that
    # starts with esp.ESP_IMAGE_MAGIC (mostly a problem for encrypted
    # images that happen to start with a magic byte
    try:
        test_image = esp.BOOTLOADER_IMAGE(io.BytesIO(image))
        test_image.verify()
    except Exception:
        print(
            "Warning: Image file at 0x%x is not a valid %s image, "
            "so not changing any flash settings." % (address, esp.CHIP_NAME)
        )
        return image

    # After the 8-byte header comes the extended header for chips others than ESP8266.
    # The 15th byte of the extended header indicates if the image is protected by
    # a SHA256 checksum. In that case we recalculate the SHA digest after modifying the header.
    sha_appended = args.chip != "esp8266" and image[8 + 15] == 1

    if args.flash_mode != "keep":
        flash_mode = FLASH_MODES[args.flash_mode]

    flash_freq = flash_size_freq & 0x0F
    if args.flash_freq != "keep":
        flash_freq = esp.parse_flash_freq_arg(args.flash_freq)

    flash_size = flash_size_freq & 0xF0
    if args.flash_size != "keep":
        flash_size = esp.parse_flash_size_arg(args.flash_size)

    flash_params = struct.pack(b"BB", flash_mode, flash_size + flash_freq)
    if flash_params != image[2:4]:
        print("Flash params set to 0x%04x" % struct.unpack(">H", flash_params))
        image = image[0:2] + flash_params + image[4:]

    # recalculate the SHA digest if it was appended
    if sha_appended:
        # Since the changes are only made for images located in the bootloader offset,
        # we can assume that the image is always a bootloader image.
        # For merged binaries, we check the bootloader SHA when parameters are changed.
        image_object = esp.BOOTLOADER_IMAGE(io.BytesIO(image))
        # get the image header, extended header (if present) and data
        image_data_before_sha = image[: image_object.data_length]
        # get the image data after the SHA digest (primary for merged binaries)
        image_data_after_sha = image[
            (image_object.data_length + image_object.SHA256_DIGEST_LEN) :
        ]

        sha_digest_calculated = hashlib.sha256(image_data_before_sha).digest()
        image = bytes(
            itertools.chain(
                image_data_before_sha, sha_digest_calculated, image_data_after_sha
            )
        )

        # get the SHA digest newly stored in the image and compare it to the calculated one
        image_stored_sha = image[
            image_object.data_length : image_object.data_length
            + image_object.SHA256_DIGEST_LEN
        ]

        if hexify(sha_digest_calculated) == hexify(image_stored_sha):
            print("SHA digest in image updated")
        else:
            print(
                "WARNING: SHA recalculation for binary failed!\n"
                f"\tExpected calculated SHA: {hexify(sha_digest_calculated)}\n"
                f"\tSHA stored in binary:    {hexify(image_stored_sha)}"
            )

    return image


def write_flash(esp, args):
    # set args.compress based on default behaviour:
    # -> if either --compress or --no-compress is set, honour that
    # -> otherwise, set --compress unless --no-stub is set
    if args.compress is None and not args.no_compress:
        args.compress = not args.no_stub

    if not args.force and esp.CHIP_NAME != "ESP8266" and not esp.secure_download_mode:
        # Check if secure boot is active
        if esp.get_secure_boot_enabled():
            for address, _ in args.addr_filename:
                if address < 0x8000:
                    raise FatalError(
                        "Secure Boot detected, writing to flash regions < 0x8000 "
                        "is disabled to protect the bootloader. "
                        "Use --force to override, "
                        "please use with caution, otherwise it may brick your device!"
                    )
        # Check if chip_id and min_rev in image are valid for the target in use
        for _, argfile in args.addr_filename:
            try:
                image = LoadFirmwareImage(esp.CHIP_NAME, argfile)
            except (FatalError, struct.error, RuntimeError):
                continue
            finally:
                argfile.seek(0)  # LoadFirmwareImage changes the file handle position
            if image.chip_id != esp.IMAGE_CHIP_ID:
                raise FatalError(
                    f"{argfile.name} is not an {esp.CHIP_NAME} image. "
                    "Use --force to flash anyway."
                )

            # this logic below decides which min_rev to use, min_rev or min/max_rev_full
            if image.max_rev_full == 0:  # image does not have max/min_rev_full fields
                use_rev_full_fields = False
            elif image.max_rev_full == 65535:  # image has default value of max_rev_full
                use_rev_full_fields = True
                if (
                    image.min_rev_full == 0 and image.min_rev != 0
                ):  # min_rev_full is not set, min_rev is used
                    use_rev_full_fields = False
            else:  # max_rev_full set to a version
                use_rev_full_fields = True

            if use_rev_full_fields:
                rev = esp.get_chip_revision()
                if rev < image.min_rev_full or rev > image.max_rev_full:
                    error_str = f"{argfile.name} requires chip revision in range "
                    error_str += (
                        f"[v{image.min_rev_full // 100}.{image.min_rev_full % 100} - "
                    )
                    if image.max_rev_full == 65535:
                        error_str += "max rev not set] "
                    else:
                        error_str += (
                            f"v{image.max_rev_full // 100}.{image.max_rev_full % 100}] "
                        )
                    error_str += f"(this chip is revision v{rev // 100}.{rev % 100})"
                    raise FatalError(f"{error_str}. Use --force to flash anyway.")
            else:
                # In IDF, image.min_rev is set based on Kconfig option.
                # For C3 chip, image.min_rev is the Minor revision
                # while for the rest chips it is the Major revision.
                if esp.CHIP_NAME == "ESP32-C3":
                    rev = esp.get_minor_chip_version()
                else:
                    rev = esp.get_major_chip_version()
                if rev < image.min_rev:
                    raise FatalError(
                        f"{argfile.name} requires chip revision "
                        f"{image.min_rev} or higher (this chip is revision {rev}). "
                        "Use --force to flash anyway."
                    )

    # In case we have encrypted files to write,
    # we first do few sanity checks before actual flash
    if args.encrypt or args.encrypt_files is not None:
        do_write = True

        if not esp.secure_download_mode:
            if esp.get_encrypted_download_disabled():
                raise FatalError(
                    "This chip has encrypt functionality "
                    "in UART download mode disabled. "
                    "This is the Flash Encryption configuration for Production mode "
                    "instead of Development mode."
                )

            crypt_cfg_efuse = esp.get_flash_crypt_config()

            if crypt_cfg_efuse is not None and crypt_cfg_efuse != 0xF:
                print("Unexpected FLASH_CRYPT_CONFIG value: 0x%x" % (crypt_cfg_efuse))
                do_write = False

            enc_key_valid = esp.is_flash_encryption_key_valid()

            if not enc_key_valid:
                print("Flash encryption key is not programmed")
                do_write = False

        # Determine which files list contain the ones to encrypt
        files_to_encrypt = args.addr_filename if args.encrypt else args.encrypt_files

        for address, argfile in files_to_encrypt:
            if address % esp.FLASH_ENCRYPTED_WRITE_ALIGN:
                print(
                    "File %s address 0x%x is not %d byte aligned, can't flash encrypted"
                    % (argfile.name, address, esp.FLASH_ENCRYPTED_WRITE_ALIGN)
                )
                do_write = False

        if not do_write and not args.ignore_flash_encryption_efuse_setting:
            raise FatalError(
                "Can't perform encrypted flash write, "
                "consult Flash Encryption documentation for more information"
            )
    else:
        if not args.force and esp.CHIP_NAME != "ESP8266":
            # ESP32 does not support `get_security_info()` and `secure_download_mode`
            if (
                esp.CHIP_NAME != "ESP32"
                and esp.secure_download_mode
                and bin(esp.get_security_info()["flash_crypt_cnt"]).count("1") & 1 != 0
            ):
                raise FatalError(
                    "WARNING: Detected flash encryption and "
                    "secure download mode enabled.\n"
                    "Flashing plaintext binary may brick your device! "
                    "Use --force to override the warning."
                )

            if (
                not esp.secure_download_mode
                and esp.get_encrypted_download_disabled()
                and esp.get_flash_encryption_enabled()
            ):
                raise FatalError(
                    "WARNING: Detected flash encryption enabled and "
                    "download manual encrypt disabled.\n"
                    "Flashing plaintext binary may brick your device! "
                    "Use --force to override the warning."
                )

    # verify file sizes fit in flash
    flash_end = flash_size_bytes(
        detect_flash_size(esp) if args.flash_size == "keep" else args.flash_size
    )
    if flash_end is not None:  # Not in secure download mode
        for address, argfile in args.addr_filename:
            argfile.seek(0, os.SEEK_END)
            if address + argfile.tell() > flash_end:
                raise FatalError(
                    "File %s (length %d) at offset %d "
                    "will not fit in %d bytes of flash. "
                    "Use --flash_size argument, or change flashing address."
                    % (argfile.name, argfile.tell(), address, flash_end)
                )
            argfile.seek(0)

    if args.erase_all:
        erase_flash(esp, args)
    else:
        for address, argfile in args.addr_filename:
            argfile.seek(0, os.SEEK_END)
            write_end = address + argfile.tell()
            argfile.seek(0)
            bytes_over = address % esp.FLASH_SECTOR_SIZE
            if bytes_over != 0:
                print(
                    "WARNING: Flash address {:#010x} is not aligned "
                    "to a {:#x} byte flash sector. "
                    "{:#x} bytes before this address will be erased.".format(
                        address, esp.FLASH_SECTOR_SIZE, bytes_over
                    )
                )
            # Print the address range of to-be-erased flash memory region
            print(
                "Flash will be erased from {:#010x} to {:#010x}...".format(
                    address - bytes_over,
                    div_roundup(write_end, esp.FLASH_SECTOR_SIZE)
                    * esp.FLASH_SECTOR_SIZE
                    - 1,
                )
            )

    """ Create a list describing all the files we have to flash.
    Each entry holds an "encrypt" flag marking whether the file needs encryption or not.
    This list needs to be sorted.

    First, append to each entry of our addr_filename list the flag args.encrypt
    E.g., if addr_filename is [(0x1000, "partition.bin"), (0x8000, "bootloader")],
    all_files will be [
        (0x1000, "partition.bin", args.encrypt),
        (0x8000, "bootloader", args.encrypt)
        ],
    where, of course, args.encrypt is either True or False
    """
    all_files = [
        (offs, filename, args.encrypt) for (offs, filename) in args.addr_filename
    ]

    """
    Now do the same with encrypt_files list, if defined.
    In this case, the flag is True
    """
    if args.encrypt_files is not None:
        encrypted_files_flag = [
            (offs, filename, True) for (offs, filename) in args.encrypt_files
        ]

        # Concatenate both lists and sort them.
        # As both list are already sorted, we could simply do a merge instead,
        # but for the sake of simplicity and because the lists are very small,
        # let's use sorted.
        all_files = sorted(all_files + encrypted_files_flag, key=lambda x: x[0])

    for address, argfile, encrypted in all_files:
        compress = args.compress

        # Check whether we can compress the current file before flashing
        if compress and encrypted:
            print("\nWARNING: - compress and encrypt options are mutually exclusive ")
            print("Will flash %s uncompressed" % argfile.name)
            compress = False

        if args.no_stub:
            print("Erasing flash...")
        image = pad_to(
            argfile.read(), esp.FLASH_ENCRYPTED_WRITE_ALIGN if encrypted else 4
        )
        if len(image) == 0:
            print("WARNING: File %s is empty" % argfile.name)
            continue

        if not esp.secure_download_mode and not esp.get_secure_boot_enabled():
            image = _update_image_flash_params(esp, address, args, image)
        else:
            print(
                "WARNING: Security features enabled, so not changing any flash settings."
            )
        calcmd5 = hashlib.md5(image).hexdigest()
        uncsize = len(image)
        if compress:
            uncimage = image
            image = zlib.compress(uncimage, 9)
            # Decompress the compressed binary a block at a time,
            # to dynamically calculate the timeout based on the real write size
            decompress = zlib.decompressobj()
            blocks = esp.flash_defl_begin(uncsize, len(image), address)
        else:
            blocks = esp.flash_begin(uncsize, address, begin_rom_encrypted=encrypted)
        argfile.seek(0)  # in case we need it again
        seq = 0
        bytes_sent = 0  # bytes sent on wire
        bytes_written = 0  # bytes written to flash
        t = time.time()

        timeout = DEFAULT_TIMEOUT

        while len(image) > 0:
            print_overwrite(
                "Writing at 0x%08x... (%d %%)"
                % (address + bytes_written, 100 * (seq + 1) // blocks)
            )
            sys.stdout.flush()
            block = image[0 : esp.FLASH_WRITE_SIZE]
            if compress:
                # feeding each compressed block into the decompressor lets us
                # see block-by-block how much will be written
                block_uncompressed = len(decompress.decompress(block))
                bytes_written += block_uncompressed
                block_timeout = max(
                    DEFAULT_TIMEOUT,
                    timeout_per_mb(ERASE_WRITE_TIMEOUT_PER_MB, block_uncompressed),
                )
                if not esp.IS_STUB:
                    timeout = (
                        block_timeout  # ROM code writes block to flash before ACKing
                    )
                esp.flash_defl_block(block, seq, timeout=timeout)
                if esp.IS_STUB:
                    # Stub ACKs when block is received,
                    # then writes to flash while receiving the block after it
                    timeout = block_timeout
            else:
                # Pad the last block
                block = block + b"\xff" * (esp.FLASH_WRITE_SIZE - len(block))
                if encrypted:
                    esp.flash_encrypt_block(block, seq)
                else:
                    esp.flash_block(block, seq)
                bytes_written += len(block)
            bytes_sent += len(block)
            image = image[esp.FLASH_WRITE_SIZE :]
            seq += 1

        if esp.IS_STUB:
            # Stub only writes each block to flash after 'ack'ing the receive,
            # so do a final dummy operation which will not be 'ack'ed
            # until the last block has actually been written out to flash
            esp.read_reg(ESPLoader.CHIP_DETECT_MAGIC_REG_ADDR, timeout=timeout)

        t = time.time() - t
        speed_msg = ""
        if compress:
            if t > 0.0:
                speed_msg = " (effective %.1f kbit/s)" % (uncsize / t * 8 / 1000)
            print_overwrite(
                "Wrote %d bytes (%d compressed) at 0x%08x in %.1f seconds%s..."
                % (uncsize, bytes_sent, address, t, speed_msg),
                last_line=True,
            )
        else:
            if t > 0.0:
                speed_msg = " (%.1f kbit/s)" % (bytes_written / t * 8 / 1000)
            print_overwrite(
                "Wrote %d bytes at 0x%08x in %.1f seconds%s..."
                % (bytes_written, address, t, speed_msg),
                last_line=True,
            )

        if not encrypted and not esp.secure_download_mode:
            try:
                res = esp.flash_md5sum(address, uncsize)
                if res != calcmd5:
                    print("File  md5: %s" % calcmd5)
                    print("Flash md5: %s" % res)
                    print(
                        "MD5 of 0xFF is %s"
                        % (hashlib.md5(b"\xFF" * uncsize).hexdigest())
                    )
                    raise FatalError("MD5 of file does not match data in flash!")
                else:
                    print("Hash of data verified.")
            except NotImplementedInROMError:
                pass

    print("\nLeaving...")

    if esp.IS_STUB:
        # skip sending flash_finish to ROM loader here,
        # as it causes the loader to exit and run user code
        esp.flash_begin(0, 0)

        # Get the "encrypted" flag for the last file flashed
        # Note: all_files list contains triplets like:
        # (address: Integer, filename: String, encrypted: Boolean)
        last_file_encrypted = all_files[-1][2]

        # Check whether the last file flashed was compressed or not
        if args.compress and not last_file_encrypted:
            esp.flash_defl_finish(False)
        else:
            esp.flash_finish(False)

    if args.verify:
        print("Verifying just-written flash...")
        print(
            "(This option is deprecated, "
            "flash contents are now always read back after flashing.)"
        )
        # If some encrypted files have been flashed,
        # print a warning saying that we won't check them
        if args.encrypt or args.encrypt_files is not None:
            print("WARNING: - cannot verify encrypted files, they will be ignored")
        # Call verify_flash function only if there is at least
        # one non-encrypted file flashed
        if not args.encrypt:
            verify_flash(esp, args)


def erase_flash(esp, args):
    if not args.force and esp.CHIP_NAME != "ESP8266" and not esp.secure_download_mode:
        if esp.get_flash_encryption_enabled() or esp.get_secure_boot_enabled():
            raise FatalError(
                "Active security features detected, "
                "erasing flash is disabled as a safety measure. "
                "Use --force to override, "
                "please use with caution, otherwise it may brick your device!"
            )
    print("Erasing flash (this may take a while)...")
    t = time.time()
    esp.erase_flash()
    print("Chip erase completed successfully in %.1fs" % (time.time() - t))


def verify_flash(esp, args):
    differences = False

    for address, argfile in args.addr_filename:
        image = pad_to(argfile.read(), 4)
        argfile.seek(0)  # rewind in case we need it again

        image = _update_image_flash_params(esp, address, args, image)

        image_size = len(image)
        print(
            "Verifying 0x%x (%d) bytes @ 0x%08x in flash against %s..."
            % (image_size, image_size, address, argfile.name)
        )
        # Try digest first, only read if there are differences.
        digest = esp.flash_md5sum(address, image_size)
        expected_digest = hashlib.md5(image).hexdigest()
        if digest == expected_digest:
            print("-- verify OK (digest matched)")
            continue
        else:
            differences = True
            if getattr(args, "diff", "no") != "yes":
                print("-- verify FAILED (digest mismatch)")
                continue

        flash = esp.read_flash(address, image_size)
        assert flash != image
        diff = [i for i in range(image_size) if flash[i] != image[i]]
        print(
            "-- verify FAILED: %d differences, first @ 0x%08x"
            % (len(diff), address + diff[0])
        )
        for d in diff:
            flash_byte = flash[d]
            image_byte = image[d]
            print("   %08x %02x %02x" % (address + d, flash_byte, image_byte))
    if differences:
        raise FatalError("Verify failed.")


# The following mapping was taken from the ROM code
# This mapping is same across all targets in the ROM
SECURITY_INFO_FLAG_MAP = {
    "SECURE_BOOT_EN": (1 << 0),
    "SECURE_BOOT_AGGRESSIVE_REVOKE": (1 << 1),
    "SECURE_DOWNLOAD_ENABLE": (1 << 2),
    "SECURE_BOOT_KEY_REVOKE0": (1 << 3),
    "SECURE_BOOT_KEY_REVOKE1": (1 << 4),
    "SECURE_BOOT_KEY_REVOKE2": (1 << 5),
    "SOFT_DIS_JTAG": (1 << 6),
    "HARD_DIS_JTAG": (1 << 7),
    "DIS_USB": (1 << 8),
    "DIS_DOWNLOAD_DCACHE": (1 << 9),
    "DIS_DOWNLOAD_ICACHE": (1 << 10),
}


# Get the status of respective security flag
def get_security_flag_status(flag_name, flags_value):
    try:
        return (flags_value & SECURITY_INFO_FLAG_MAP[flag_name]) != 0
    except KeyError:
        raise ValueError(f"Invalid flag name: {flag_name}")


def version(args):
    from . import __version__

    print(__version__)
