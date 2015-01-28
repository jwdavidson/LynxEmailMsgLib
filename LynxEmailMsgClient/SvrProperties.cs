using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LynxEmailMsgClient
{
    public class SvrProperties
    {
        public SvrProperties()
        {
            DistinguishedNameBare = "LynxEmailSysSvr_2001:470:1d:80b:e5b6:2d69:3897:336a";
            CertificateExtOID = "1.3.6.1.4.1.45177.1.1";
        }
        public string DistinguishedNameBare { get; set; }
        public string CertificateExtOID { get; set; }

    }
}
