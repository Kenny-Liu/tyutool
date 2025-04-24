cd `dirname $0`

if [ x"-d" = x"$1" ]; then
    PDB="-m pdb"
fi

# ESP32S3
# python ${PDB} ./esptool.py --chip esp32s3 -p /dev/ttyUSB0 -b 460800 --before default_reset --after hard_reset write_flash --flash_mode dio --flash_size 2MB --flash_freq 80m 0x0 esp32s3_bin/bootloader.bin 0x8000 esp32s3_bin/partition-table.bin 0x10000 esp32s3_bin/hello_world.bin
# python ${PDB} ./esptool.py --chip esp32s3 -p /dev/ttyUSB0 -b 460800 --before default_reset --after hard_reset write_flash --flash_mode dio --flash_size 2MB --flash_freq 80m 0x0 esp32s3_bin/QIO.bin

# ESP32
# python ${PDB} ./esptool.py --chip esp32 -p /dev/ttyUSB0 -b 460800 --before default_reset --after hard_reset write_flash --flash_mode dio --flash_size 2MB --flash_freq 40m 0x1000 esp32_bin/bootloader.bin 0x8000 esp32_bin/partition-table.bin 0x10000 esp32_bin/hello_world.bin
# python ${PDB} ./esptool.py -t --chip esp32 -p /dev/ttyUSB0 -b 460800 --before default_reset --after hard_reset write_flash --flash_mode dio --flash_size 2MB --flash_freq 40m 0x0 ./esp32_bin/QIO.bin

# ESP32C3
# python ${PDB} ./esptool.py --chip esp32c3 -p /dev/ttyACM0 -b 460800 --before default_reset --after hard_reset write_flash --flash_mode dio --flash_size 2MB --flash_freq 80m 0x0 esp32c3_bin/bootloader.bin 0x8000 esp32c3_bin/partition-table.bin 0x10000 esp32c3_bin/hello_world.bin
python ${PDB} ./esptool.py --chip esp32c3 -p /dev/ttyACM0 -b 460800 --before default_reset --after hard_reset write_flash --flash_mode dio --flash_size 2MB --flash_freq 80m 0x0 esp32c3_bin/QIO.bin
