/*
* You can get custom variables: $vars.<variable-name>
* Must return a string value at the end of function
*/

const crypto = require("crypto");
const https = require("https");

// AWS Credentials (stored securely in Flowise)
const AWS_REGION = $vars.AWS_REGION; 
const ACCESS_KEY = $vars.AWS_ACCESS_KEY_ID;
const SECRET_KEY = $vars.AWS_SECRET_ACCESS_KEY;
const EMAIL_FROM = $vars.AWS_EMAIL_SENDER; // Must be verified in AWS SES

// Construct the email request payload
const emailPayload = JSON.stringify({
    FromEmailAddress: EMAIL_FROM,
    Destination: {
        ToAddresses: [$Recipient]
    },
    Content: {
        Simple: {
            Subject: { Data: $Subject },
            Body: {
                Text: { Data: $Body }
            }
        }
    }
});

// Function to create AWS Signature v4
function createSignatureKey(key, dateStamp, region, service) {
    let kDate = crypto.createHmac("sha256", "AWS4" + key).update(dateStamp).digest();
    let kRegion = crypto.createHmac("sha256", kDate).update(region).digest();
    let kService = crypto.createHmac("sha256", kRegion).update(service).digest();
    return crypto.createHmac("sha256", kService).update("aws4_request").digest();
}

// Generate AWS signature
const date = new Date();
const amzDate = date.toISOString().replace(/[:-]|\.\d{3}/g, '');
const dateStamp = date.toISOString().split("T")[0].replace(/-/g, '');

const canonicalRequest = `POST
/v2/email/outbound-emails

content-type:application/json
host:email.${AWS_REGION}.amazonaws.com
x-amz-date:${amzDate}

content-type;host;x-amz-date
${crypto.createHash("sha256").update(emailPayload).digest("hex")}`;

const algorithm = "AWS4-HMAC-SHA256";
const credentialScope = `${dateStamp}/${AWS_REGION}/ses/aws4_request`;
const stringToSign = `${algorithm}
${amzDate}
${credentialScope}
${crypto.createHash("sha256").update(canonicalRequest).digest("hex")}`;

const signingKey = createSignatureKey(SECRET_KEY, dateStamp, AWS_REGION, "ses");
const signature = crypto.createHmac("sha256", signingKey).update(stringToSign).digest("hex");

// Authorization header
const authorizationHeader = `${algorithm} Credential=${ACCESS_KEY}/${credentialScope}, SignedHeaders=content-type;host;x-amz-date, Signature=${signature}`;

// HTTPS request options
const options = {
    hostname: `email.${AWS_REGION}.amazonaws.com`,
    path: "/v2/email/outbound-emails",
    method: "POST",
    headers: {
        "Content-Type": "application/json",
        "X-Amz-Date": amzDate,
        "Authorization": authorizationHeader
    }
};

// Send request to SES
return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
        let responseData = '';
        res.on("data", (chunk) => responseData += chunk);
        res.on("end", () => {
            if (res.statusCode === 200) {
                resolve(`Email sent successfully! Response: ${responseData}`);
            } else {
                reject(`SES Error: ${responseData}`);
            }
        });
    });

    req.on("error", (error) => reject(`Failed to send email: ${error.message}`));
    req.write(emailPayload);
    req.end();
});
