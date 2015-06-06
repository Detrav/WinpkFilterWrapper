using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Detrav.WinpkFilterWrapper
{
    public class TcpFilter : IDisposable
    {
        #region Переменные
        private IntPtr driverPtr;
        private TCP_AdapterList adapters;
        private INTERMEDIATE_BUFFER buffer;
        private IntPtr bufferPtr;
        private ETH_REQUEST request;
        private static TcpFilter instance;
        private Thread thread;
        private bool needToStop;
        private bool ready;
        //private string host;
        /// <summary>
        /// Фильтр на хост
        /// </summary>
        public string host { get; set; }
        #endregion Переменные

        private TcpFilter()
        {
            driverPtr = Ndisapi.OpenFilterDriver();
            adapters = new TCP_AdapterList();
            needToStop = false;
            GCHandle.Alloc(adapters);
            if ((Ndisapi.IsDriverLoaded(driverPtr)))
            {
                ready = Ndisapi.GetTcpipBoundAdaptersInfo(driverPtr, ref adapters);
            }
            thread = new Thread(doEvents);
        }



        //Похоже на синглтон, но это не так, это что то среднее между синглтоном и обычным классом
        /// <summary>
        /// Создаёт новый экземляр класса, если уже существует, то уничтожает его и создаёт новый, таким образом всегда будет только 1 представитель
        /// </summary>
        /// <returns>CaptureDevice</returns>
        public static TcpFilter create()
        {
            if (instance != null) instance.Dispose();
            instance = new TcpFilter();
            return instance;
        }
        /// <summary>
        /// Список названия устройств.
        /// </summary>
        public string[] deviceList
        {
            get
            {
                string[] strs = new string[adapters.m_nAdapterCount];
                for (int i = 0; i < strs.Length; i++)
                {
                    strs[i] = adapters.GetName(i);
                }
                return strs;
            }
        }

        public bool startASync(int deviceNumber)
        {
            if (!ready) return false;
            try
            {
                ADAPTER_MODE mode = new ADAPTER_MODE
                {
                    dwFlags = Ndisapi.MSTCP_FLAG_SENT_LISTEN | Ndisapi.MSTCP_FLAG_RECV_LISTEN,
                    hAdapterHandle = adapters.m_nAdapterHandle[deviceNumber]
                };
                Ndisapi.SetAdapterMode(driverPtr, ref mode);
                if (host != null)
                {
                    IP_ADDRESS_V4 serverIp = new IP_ADDRESS_V4()
                        {
                            m_AddressType = Ndisapi.IP_SUBNET_V4_TYPE,
                            m_IpSubnet = new IP_SUBNET_V4
                            {
                                m_Ip = BitConverter.ToUInt32(IPAddress.Parse(host).GetAddressBytes(), 0),
                                m_IpMask = 0xFFFFFFFF
                            }
                        };
                    STATIC_FILTER_TABLE filtersTable = new STATIC_FILTER_TABLE();
                    filtersTable.m_StaticFilters = new STATIC_FILTER[256];
                    filtersTable.m_TableSize = 3;

                    filtersTable.m_StaticFilters[0].m_Adapter = 0; // applied to all adapters
                    filtersTable.m_StaticFilters[0].m_ValidFields = Ndisapi.NETWORK_LAYER_VALID;
                    filtersTable.m_StaticFilters[0].m_FilterAction = Ndisapi.FILTER_PACKET_REDIRECT;

                    filtersTable.m_StaticFilters[0].m_dwDirectionFlags = Ndisapi.PACKET_FLAG_ON_SEND;
                    filtersTable.m_StaticFilters[0].m_NetworkFilter.m_dwUnionSelector = Ndisapi.IPV4;
                    filtersTable.m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_ValidFields = Ndisapi.IP_V4_FILTER_DEST_ADDRESS;

                    filtersTable.m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_DestAddress = serverIp;

                    filtersTable.m_StaticFilters[1].m_Adapter = 0; // applied to all adapters
                    filtersTable.m_StaticFilters[1].m_ValidFields = Ndisapi.NETWORK_LAYER_VALID;
                    filtersTable.m_StaticFilters[1].m_FilterAction = Ndisapi.FILTER_PACKET_REDIRECT;

                    filtersTable.m_StaticFilters[1].m_dwDirectionFlags = Ndisapi.PACKET_FLAG_ON_RECEIVE;
                    filtersTable.m_StaticFilters[1].m_NetworkFilter.m_dwUnionSelector = Ndisapi.IPV4;
                    filtersTable.m_StaticFilters[1].m_NetworkFilter.m_IPv4.m_ValidFields = Ndisapi.IP_V4_FILTER_SRC_ADDRESS;

                    filtersTable.m_StaticFilters[1].m_NetworkFilter.m_IPv4.m_SrcAddress = serverIp;

                    filtersTable.m_StaticFilters[2].m_Adapter = 0; // applied to all adapters
                    filtersTable.m_StaticFilters[2].m_ValidFields = 0;
                    filtersTable.m_StaticFilters[2].m_FilterAction = Ndisapi.FILTER_PACKET_PASS;
                    filtersTable.m_StaticFilters[2].m_dwDirectionFlags = Ndisapi.PACKET_FLAG_ON_RECEIVE | Ndisapi.PACKET_FLAG_ON_SEND;
                    Ndisapi.SetPacketFilterTable(driverPtr, ref filtersTable);
                }

                buffer = new INTERMEDIATE_BUFFER();
                bufferPtr = Marshal.AllocHGlobal(Marshal.SizeOf(buffer));
                Win32Api.ZeroMemory(bufferPtr, Marshal.SizeOf(buffer));
                request = new ETH_REQUEST
                {
                    hAdapterHandle = adapters.m_nAdapterHandle[deviceNumber],
                    EthPacket = { Buffer = bufferPtr }
                };
                thread.Start();
                ready = false;
                return true;
            }
            catch { return false; }
        }

        #region Dispose
        bool disposed = false;
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        protected virtual void Dispose(bool disposing)
        {
            if (disposed)
                return;
            if (disposing)
            {
                try
                {
                    if (thread != null)
                    {
                        needToStop = true;
                        thread.Join();
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(bufferPtr);
                    Ndisapi.CloseFilterDriver(driverPtr);
                }
            }
            disposed = true;
        }
        #endregion Dispose

        private void doEvents(object obj)
        {
            while (true)
            {
                if (needToStop) return;
                if (Ndisapi.ReadPacket(driverPtr, ref request))
                {
                    buffer = (INTERMEDIATE_BUFFER)Marshal.PtrToStructure(bufferPtr, typeof(INTERMEDIATE_BUFFER));
                    //Тут нужен мульти лок
                    //captureDevice_OnPacketArrival(buffer);
                }
                else System.Threading.Thread.Sleep(16);
            }
        }
    }
}