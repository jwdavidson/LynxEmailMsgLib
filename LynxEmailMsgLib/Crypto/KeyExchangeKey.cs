﻿//
// This code originated with Keith Brown (pluralsight.com), and may be freely used.
//
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace LynxEmailMsgLib.Crypto
{
    public class KeyExchangeKey : CryptKey
    {
        internal KeyExchangeKey(CryptContext ctx, IntPtr handle) : base(ctx, handle)  {}
        
        public override KeyType Type
        {
            get { return KeyType.Exchange; }
        }
    }
}
