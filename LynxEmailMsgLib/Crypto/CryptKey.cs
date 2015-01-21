//
// This code originated with Keith Brown (pluralsight.com), and may be freely used.
//
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace LynxEmailMsgLib.Crypto
{
    public abstract class CryptKey : DisposeableObject
    {
        CryptContext ctx;
        IntPtr handle;

        internal IntPtr Handle { get { return handle; } }

        internal CryptKey(CryptContext ctx, IntPtr handle)
        {
            this.ctx = ctx;
            this.handle = handle;
        }

        public abstract KeyType Type { get; }

        protected override void CleanUp(bool viaDispose)
        {
            // keys are invalid once CryptContext is closed,
            // so the only time I try to close an individual key is if a user
            // explicitly disposes of the key.
            if (viaDispose)
                ctx.DestroyKey(this);
        }
    }
}
