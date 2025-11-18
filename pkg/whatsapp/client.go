package whatsapp

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

type Client struct {
    APIKey        string
    BaseURL       string
    PhoneNumberID string
    BusinessID    string
    HTTPClient    *http.Client
}

func NewClient(apiKey, baseURL, phoneNumberID, businessID string) *Client {
    return &Client{
        APIKey:        apiKey,
        BaseURL:       baseURL,
        PhoneNumberID: phoneNumberID,
        BusinessID:    businessID,
        HTTPClient:    &http.Client{
            Timeout: time.Second * 10,
        },
    }
}

// WhatsAppResponse represents the API response structure
type WhatsAppResponse struct {
    MessagingProduct string `json:"messaging_product"`
    Contacts  []struct {
        WaID string `json:"wa_id"`
    } `json:"contacts"`
    Messages []struct {
        ID string `json:"id"`
    } `json:"messages"`
    Error *struct {
        Message string `json:"message"`
        Type    string `json:"type"`
        Code    int    `json:"code"`
    } `json:"error,omitempty"`
}

// SendOTP sends a WhatsApp OTP message using the Cloud API
func (c *Client) SendOTP(phoneNumber, otp string) error {
    // Format phone number (remove any '+' prefix)
    formattedPhone := phoneNumber
    if len(phoneNumber) > 0 && phoneNumber[0] == '+' {
        formattedPhone = phoneNumber[1:]
    }
    
    // API endpoint
    endpoint := fmt.Sprintf("%s/v15.0/%s/messages", c.BaseURL, c.PhoneNumberID)
    
    // Define message payload using your pre-approved template
    templateData := map[string]interface{}{
        "messaging_product": "whatsapp",
        "to": formattedPhone,
        "type": "template",
        "template": map[string]interface{}{
            "name": "otp_verification", // Your pre-approved template name
            "language": map[string]string{
                "code": "en_US",
            },
            "components": []map[string]interface{}{
                {
                    "type": "body",
                    "parameters": []map[string]interface{}{
                        {
                            "type": "text",
                            "text": otp,
                        },
                    },
                },
            },
        },
    }
    
    // Convert payload to JSON
    jsonData, err := json.Marshal(templateData)
    if err != nil {
        return fmt.Errorf("error marshaling WhatsApp message: %w", err)
    }
    
    // Create request
    req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
    if err != nil {
        return fmt.Errorf("error creating WhatsApp API request: %w", err)
    }
    
    // Set headers
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer " + c.APIKey)
    
    // Send the request
    resp, err := c.HTTPClient.Do(req)
    if err != nil {
        return fmt.Errorf("error sending WhatsApp message: %w", err)
    }
    defer resp.Body.Close()
    
    // Handle response
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        var errorResp WhatsAppResponse
        json.NewDecoder(resp.Body).Decode(&errorResp)
        
        if errorResp.Error != nil {
            return fmt.Errorf("WhatsApp API error: %s (code: %d)", 
                errorResp.Error.Message, errorResp.Error.Code)
        }
        return fmt.Errorf("WhatsApp API returned status %d", resp.StatusCode)
    }
    
    fmt.Printf("Successfully sent WhatsApp OTP to %s\n", phoneNumber)
    return nil
}
