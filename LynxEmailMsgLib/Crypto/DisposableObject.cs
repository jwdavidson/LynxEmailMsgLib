//
// This code originated with Keith Brown (pluralsight.com), and may be freely used.
//
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace LynxEmailMsgLib.Crypto
{
    [StructLayout(LayoutKind.Sequential)]
    public abstract class DisposeableObject : IDisposable
    {
        private bool disposed = false;

        ~DisposeableObject()
        {
            CleanUp(false);
        }

        public void Dispose()
        {
            // note this method does not throw ObjectDisposedException
            if (!disposed)
            {
                CleanUp(true);

                disposed = true;

                GC.SuppressFinalize(this);
            }
        }

        protected abstract void CleanUp(bool viaDispose);

        /// <summary>
        /// Typical check for derived classes
        /// </summary>
        protected void ThrowIfDisposed()
        {
            ThrowIfDisposed(this.GetType().FullName);
        }

        /// <summary>
        /// Typical check for derived classes
        /// </summary>
        protected void ThrowIfDisposed(string objectName)
        {
            if (disposed)
                throw new ObjectDisposedException(objectName);
        }
    }
}
