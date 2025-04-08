package org.zaproxy.clientapi.core;

/**
 * Stub implementation of the ZAP Client API.
 * This is a placeholder that enables compilation without the actual ZAP API.
 */
public class ClientApi {
    
    public final CoreAPI core;
    public final PscanAPI pscan;
    public final AscanAPI ascan;
    public final SpiderAPI spider;
    public final AjaxSpiderAPI ajaxSpider;
    public final ContextAPI context;
    public final Authentication authentication;
    public final Script script;
    public final UsersAPI users;
    public final Reports reports;
    
    /**
     * Creates a new ZAP client API with the specified parameters.
     * 
     * @param zapHost The ZAP host
     * @param zapPort The ZAP port
     * @param apiKey The API key
     */
    public ClientApi(String zapHost, int zapPort, String apiKey) {
        this.core = new CoreAPI();
        this.pscan = new PscanAPI();
        this.ascan = new AscanAPI();
        this.spider = new SpiderAPI();
        this.ajaxSpider = new AjaxSpiderAPI();
        this.context = new ContextAPI();
        this.authentication = new Authentication();
        this.script = new Script();
        this.users = new UsersAPI();
        this.reports = new Reports();
    }
    
    /**
     * Creates a new ZAP client API with a default API key.
     * 
     * @param zapHost The ZAP host
     * @param zapPort The ZAP port
     */
    public ClientApi(String zapHost, int zapPort) {
        this(zapHost, zapPort, "");
    }
}
