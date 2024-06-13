namespace Islandsbanki.OpenBanking
{
  public class AppConfiguration
  {
    public string PaymentBaseAddress {get; set;}
    public string AuthBaseAddress {get; set;}
    public string AuthorizationEndpoint {get; set;}
    public string TokenEndpoint {get; set;}
    public string ClientId {get; set;}
    public string ClientSecret {get; set;}
    public string RedirectUri {get; set;}
    public string Scopes {get; set;}
    public string AccountsUri {get; set;}
    public string DebtorAccount {get; set;}
    public string CreditorAccount {get; set;}
    public string AuthHeaderName {get; set;}
    public string QwacCertName {get; set;}
    public string QwacCertPassword {get; set;}
    public string QsealPem {get; set;}
    public string QsealKey {get; set;}
  }
}
