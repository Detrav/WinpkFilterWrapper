using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Detrav.WinpkFilterWrapper
{
    public class FilterPacketArrivalEventArgs : EventArgs
    {
        public byte[] payloadData { get; private set; }
        public FilterPacketArrivalEventArgs(byte[] data)
        {
            payloadData = data;
        }
    }

    public delegate void OnFilterPacketArrival(object sender, FilterPacketArrivalEventArgs e);
}
