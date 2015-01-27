using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;

namespace LynxEmailMsgLib.Tests
{
    [TestClass]
    public class XmlDocTests
    {

        [TestMethod]
        public void TestMethod1_CreateXmlFromDoc()
        {
            // this gets a file and inserts it into an XML document which is saved
            byte[] bytes = File.ReadAllBytes(@"C:\Users\John\Documents\Test XML.docx");
            Assert.IsTrue(bytes.LongCount() > 1000);

            XDocument doc = new XDocument(
                new XDeclaration("1.0", "utf-16", "true"),
                new XElement("InputFile", Convert.ToBase64String(bytes)));

            doc.Save(@"C:\Users\John\Documents\Test XML.xml");

        }

        [TestMethod]
        public void TestMethd2_CreateDocFromXml()
        {
            // this gets the XML document and extracts the previously saved file data 
            //     and then stores it in a second file.
            XDocument doc = XDocument.Load(@"C:\Users\John\Documents\Test XML.xml");
            byte[] bytes = Convert.FromBase64String(doc.Element("InputFile").Value);
            Assert.IsTrue(bytes.LongCount() > 1000);

            SHA512 shaM = new SHA512Managed();
            byte[] inputResult = shaM.ComputeHash(bytes);

            byte[] fileBytes = File.ReadAllBytes(@"C:\Users\John\Documents\Test XML.docx");
            byte[] fileResult = shaM.ComputeHash(fileBytes);

            bool bEqual = false;
            if (inputResult.Length == fileResult.Length) {
                int i = 0;
                while ((i < inputResult.Length) && (inputResult[i] == fileResult[i])) {
                    i += 1;
                }
                if (i == inputResult.Length) { bEqual = true; }
            }
            Assert.IsTrue(bEqual);
            
            File.WriteAllBytes(@"C:\Users\John\Documents\TestOutput XML.doc", bytes);
            
        }
    }
}
