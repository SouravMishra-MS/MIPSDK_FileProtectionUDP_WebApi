using Microsoft.InformationProtection;

namespace MIPSDK_FileOperations_API.Services
{
    internal class ConsentDelegateImpl : IConsentDelegate
    {
        public Consent GetUserConsent(string url)
        {
            return Consent.Accept;
        }
    }
}
