package org.zaproxy.clientapi.core;

/**
 * Stub implementation of the ZAP ApiResponseElement class.
 * This is a placeholder that enables compilation without the actual ZAP API.
 */
public class ApiResponseElement extends ApiResponse {
    private String name;
    private String value;
    
    /**
     * Constructor for the ApiResponseElement.
     * 
     * @param name The name of the element
     * @param value The value of the element
     */
    public ApiResponseElement(String name, String value) {
        this.name = name;
        this.value = value;
    }
    
    /**
     * Gets the name of the element.
     * 
     * @return The name of the element
     */
    public String getName() {
        return name;
    }
    
    /**
     * Gets the value of the element.
     * 
     * @return The value of the element
     */
    public String getValue() {
        return value;
    }
    
    @Override
    public String toString() {
        return String.format("<%s>%s</%s>", name, value, name);
    }
    
    /**
     * Overloaded toString method to handle specific format requirements.
     * 
     * @param format The format to use
     * @return The formatted string
     */
    public String toString(int format) {
        if (format == 0) {
            return toString();
        } else if (format == 1) {
            return value;
        } else {
            return String.format("{\"%s\": \"%s\"}", name, value);
        }
    }
}
