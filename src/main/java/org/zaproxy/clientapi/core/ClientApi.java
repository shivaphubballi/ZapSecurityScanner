package org.zaproxy.clientapi.core;

/**
 * Stub implementation of the ZAP ClientApi class.
 * This is a placeholder that enables compilation without the actual ZAP API.
 */
public class ClientApi {
    
    // API components
    public final CoreAPI core = new CoreAPI();
    public final SpiderAPI spider = new SpiderAPI();
    public final AjaxSpiderAPI ajaxSpider = new AjaxSpiderAPI();
    public final ContextAPI context = new ContextAPI();
    public final UsersAPI users = new UsersAPI();
    public final AscanAPI ascan = new AscanAPI();
    public final PscanAPI pscan = new PscanAPI();
    public final Authentication authentication = new Authentication();
    public final Reports reports = new Reports();
    public final Script script = new Script();
    
    private final String zapAddress;
    private final int zapPort;
    private final String apiKey;
    
    /**
     * Constructor for the ClientApi.
     * 
     * @param zapAddress The ZAP address
     * @param zapPort The ZAP port
     * @param apiKey The API key, or null if not required
     */
    public ClientApi(String zapAddress, int zapPort, String apiKey) {
        this.zapAddress = zapAddress;
        this.zapPort = zapPort;
        this.apiKey = apiKey;
    }
    
    /**
     * Constructor for the ClientApi.
     * 
     * @param zapAddress The ZAP address
     * @param zapPort The ZAP port
     */
    public ClientApi(String zapAddress, int zapPort) {
        this(zapAddress, zapPort, null);
    }
}
