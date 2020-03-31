using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApplication2
{
    using System;
    using System.IO.Ports;
    using System.Threading;

    public class Program
    {
        static bool _continue;
        static SerialPort _serialPort;

        static void Main()
        {
            string message;
            StringComparer stringComparer = StringComparer.OrdinalIgnoreCase;
            Thread readThread = new Thread(Read);
           
            _serialPort = new SerialPort(); //创建串口对象

            Init();                 //初始化(输出默认值)

            //设定超时时间
            _serialPort.ReadTimeout = 500;
            _serialPort.WriteTimeout = 500;

            _serialPort.Open();
            _continue = true;
            readThread.Start();

            Console.WriteLine(  "\"quit\"退出");

            while (_continue)
            {
                message = Console.ReadLine();

                if (stringComparer.Equals("quit", message))
                {
                    _continue = false;
                }
                else
                {
                    System.DateTime currentTime = new System.DateTime();
                    currentTime = System.DateTime.Now;
                    string strTime = currentTime.ToString();
                    message = "[SENT " + strTime + "] " + message;
                    Console.WriteLine(message);
                    _serialPort.WriteLine(String.Format("{0}", message));

                }
            }

            readThread.Join();
            _serialPort.Close();
        }

        static void Read()
        {
            while (_continue)
            {
                try
                {
                    string message = _serialPort.ReadLine();
                    System.DateTime currentTime = new System.DateTime();
                    currentTime = System.DateTime.Now;
                    string strTime = currentTime.ToString();
                    message = "[REVC " + strTime + "] " + message;
                    Console.WriteLine(message);
                }
                catch (TimeoutException) { }
            }
        }

        //设置端口(使用默认值)
        static void Init()
        {
            string portName;

            Console.WriteLine("可用端口:");
            foreach (string s in SerialPort.GetPortNames())
            {
                Console.WriteLine("{0}", s);
            }

            Console.Write("设置 COM 端口: ");
            portName = Console.ReadLine();

            _serialPort.PortName = portName;

            Console.WriteLine("波特率:{0} ", _serialPort.BaudRate.ToString());
            Console.WriteLine("奇偶值:{0} ", _serialPort.Parity.ToString());
            Console.WriteLine("数据位:{0} ", _serialPort.DataBits.ToString());
            Console.WriteLine("停止位:{0} ", _serialPort.StopBits.ToString());
            Console.WriteLine("握手协议:{0} ", _serialPort.Handshake.ToString());
        }       
    }
}