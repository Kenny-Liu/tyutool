import { useState, useRef, useEffect } from 'react'
import { ArrowUpTrayIcon, ArrowDownTrayIcon } from '@heroicons/react/24/outline'
import toast, { Toaster } from 'react-hot-toast'

const BAUD_RATES = [115200, 230400, 460800, 921600, 1500000, 2000000]

declare global {
  interface Navigator {
    serial: {
      getPorts: () => Promise<SerialPort[]>
      requestPort: () => Promise<SerialPort>
    }
  }
}

export default function App() {
  const [port, setPort] = useState<SerialPort | null>(null)
  const [ports, setPorts] = useState<SerialPort[]>([])
  const [baudRate, setBaudRate] = useState(921600)
  const [file, setFile] = useState<File | null>(null)
  const [logs, setLogs] = useState<string[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const logsEndRef = useRef<HTMLDivElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    // Scroll logs to bottom when new logs are added
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  const refreshPorts = async () => {
    try {
      const availablePorts = await navigator.serial.getPorts()
      setPorts(availablePorts)
    } catch (err) {
      toast.error('Failed to get serial ports')
    }
  }

  const connectPort = async () => {
    try {
      const selectedPort = await navigator.serial.requestPort()
      await selectedPort.open({ baudRate })
      setPort(selectedPort)
      setIsConnected(true)
      toast.success('Connected to serial port')
      
      // Start reading from the serial port
      while (selectedPort.readable) {
        const reader = selectedPort.readable.getReader()
        try {
          while (true) {
            const { value, done } = await reader.read()
            if (done) break
            const text = new TextDecoder().decode(value)
            setLogs(prev => [...prev, text])
          }
        } catch (error) {
          console.error(error)
        } finally {
          reader.releaseLock()
        }
      }
    } catch (err) {
      toast.error('Failed to connect to serial port')
    }
  }

  const disconnectPort = async () => {
    try {
      if (port) {
        await port.close()
        setPort(null)
        setIsConnected(false)
        toast.success('Disconnected from serial port')
      }
    } catch (err) {
      toast.error('Failed to disconnect from serial port')
    }
  }

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files
    if (files && files[0]) {
      setFile(files[0])
      toast.success('File selected')
    }
  }

  const handleFlash = async () => {
    if (!port || !file) {
      toast.error('Please connect port and select file first')
      return
    }

    try {
      // Here we would implement the T5 flashing protocol
      toast.success('Flashing started')
      // Add actual flashing implementation
    } catch (err) {
      toast.error('Failed to flash firmware')
    }
  }

  const clearLogs = () => {
    setLogs([])
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="bg-white rounded-lg shadow p-6">
          <h1 className="text-2xl font-bold text-gray-900 mb-6">T5 Module Firmware Flasher</h1>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-6">
              <div>
                <label className="block text-sm font-medium text-gray-700">Serial Port</label>
                <div className="mt-1 flex space-x-2">
                  <button
                    onClick={connectPort}
                    disabled={isConnected}
                    className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:bg-gray-400"
                  >
                    Connect
                  </button>
                  <button
                    onClick={disconnectPort}
                    disabled={!isConnected}
                    className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:bg-gray-400"
                  >
                    Disconnect
                  </button>
                  <button
                    onClick={refreshPorts}
                    className="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md shadow-sm text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                  >
                    Refresh
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">Baud Rate</label>
                <select
                  value={baudRate}
                  onChange={(e) => setBaudRate(Number(e.target.value))}
                  className="mt-1 block w-full pl-3 pr-10 py-2 text-base border-gray-300 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm rounded-md"
                >
                  {BAUD_RATES.map(rate => (
                    <option key={rate} value={rate}>{rate}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">Firmware File</label>
                <div className="mt-1 flex space-x-2">
                  <input
                    type="file"
                    ref={fileInputRef}
                    onChange={handleFileChange}
                    accept=".bin"
                    className="hidden"
                  />
                  <button
                    onClick={() => fileInputRef.current?.click()}
                    className="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md shadow-sm text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                  >
                    <ArrowUpTrayIcon className="h-5 w-5 mr-2" />
                    Select File
                  </button>
                  <button
                    onClick={() => {/* Implement remote file download */}}
                    className="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md shadow-sm text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                  >
                    <ArrowDownTrayIcon className="h-5 w-5 mr-2" />
                    Download Remote
                  </button>
                </div>
                {file && (
                  <p className="mt-2 text-sm text-gray-500">
                    Selected: {file.name}
                  </p>
                )}
              </div>

              <button
                onClick={handleFlash}
                disabled={!isConnected || !file}
                className="w-full inline-flex justify-center items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 disabled:bg-gray-400"
              >
                Flash Firmware
              </button>
            </div>

            <div>
              <div className="flex justify-between items-center mb-2">
                <label className="block text-sm font-medium text-gray-700">Serial Logs</label>
                <button
                  onClick={clearLogs}
                  className="text-sm text-gray-500 hover:text-gray-700"
                >
                  Clear
                </button>
              </div>
              <div className="h-96 bg-gray-900 rounded-lg p-4 overflow-auto">
                <pre className="text-green-400 font-mono text-sm whitespace-pre-wrap">
                  {logs.join('')}
                </pre>
                <div ref={logsEndRef} />
              </div>
            </div>
          </div>
        </div>
      </div>
      <Toaster position="top-right" />
    </div>
  )
}