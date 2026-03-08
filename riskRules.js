function generateRiskSignals(crawlData, domainRisks = []) {

const risks = [];

const {
totalLinks = 0,
externalLinks = 0,
emails = [],
phones = [],
metaDescription,
socialLinks = [],
loginForms = 0,
paymentSignals = 0,
suspiciousSignals = 0,
hasPrivacyPolicy,
hasTerms,
redirects,
hiddenElements = 0,
iframeCount = 0,
domainAgeDays,
suspiciousTLD
} = crawlData;


// DOMAIN INTELLIGENCE

if(domainRisks.length > 0){
domainRisks.forEach(r => risks.push(r));
}

if(domainAgeDays !== null){

if(domainAgeDays < 30){

risks.push({
element:"Domain Age",
rule:"Very new domain detected",
severity:"High",
category:"Domain Intelligence",
reason:"Fraud websites are often created very recently"
});

}

else if(domainAgeDays < 180){

risks.push({
element:"Domain Age",
rule:"Recently created domain",
severity:"Medium",
category:"Domain Intelligence",
reason:"New domains have higher fraud probability"
});

}

}

if(suspiciousTLD){

risks.push({
element:"Domain TLD",
rule:"Suspicious top-level domain",
severity:"Medium",
category:"Domain Intelligence",
reason:"Certain TLDs are commonly used in scam domains"
});

}


// CONTACT SIGNALS

if(emails.length === 0 && phones.length === 0){

risks.push({
element:"Contact Information",
rule:"No contact details found",
severity:"High",
category:"Trust Signals",
reason:"Legitimate businesses normally provide contact information"
});

}

if(phones.length > 5){

risks.push({
element:"Contact Information",
rule:"Too many phone numbers detected",
severity:"Low",
category:"Trust Signals",
reason:"Excessive phone numbers may indicate lead-generation pages"
});

}


// LEGAL SIGNALS

if(!hasPrivacyPolicy){

risks.push({
element:"Legal Compliance",
rule:"Missing privacy policy",
severity:"Medium",
category:"Compliance Risk",
reason:"Privacy policies are expected on legitimate merchant sites"
});

}

if(!hasTerms){

risks.push({
element:"Legal Compliance",
rule:"Missing terms and conditions",
severity:"Medium",
category:"Compliance Risk",
reason:"Terms of service pages are required for merchant operations"
});

}


// WEBSITE QUALITY

if(!metaDescription){

risks.push({
element:"SEO Metadata",
rule:"Missing meta description",
severity:"Low",
category:"Website Quality",
reason:"Professional websites normally include metadata"
});

}

if(totalLinks < 5){

risks.push({
element:"Website Structure",
rule:"Very few internal links",
severity:"Low",
category:"Website Quality",
reason:"Legitimate websites normally have richer navigation"
});

}


// LINK STRUCTURE

if(externalLinks > 20){

risks.push({
element:"Link Structure",
rule:"Too many external links",
severity:"Medium",
category:"Spam Risk",
reason:"Excessive outbound links can indicate spam or affiliate pages"
});

}

if(externalLinks > totalLinks * 0.5 && totalLinks > 10){

risks.push({
element:"Link Structure",
rule:"High external link ratio",
severity:"Medium",
category:"Spam Risk",
reason:"More than half of the links point outside the website"
});

}


// PAYMENT SIGNALS

if(paymentSignals > 2){

risks.push({
element:"Payment Behaviour",
rule:"Multiple payment keywords detected",
severity:"Medium",
category:"Transaction Risk",
reason:"Pages requesting payments should be verified carefully"
});

}


// AUTHENTICATION

if(loginForms > 2){

risks.push({
element:"Authentication",
rule:"Multiple login forms detected",
severity:"Medium",
category:"Security Signals",
reason:"Multiple login forms can indicate phishing behaviour"
});

}


// SOCIAL TRUST

if(socialLinks.length === 0){

risks.push({
element:"Brand Presence",
rule:"No social media presence",
severity:"Low",
category:"Trust Signals",
reason:"Legitimate brands often link official social media pages"
});

}


// FRAUD CONTENT

if(suspiciousSignals > 0){

risks.push({
element:"Content Analysis",
rule:"Suspicious marketing language detected",
severity:"High",
category:"Fraud Signals",
reason:"Common scam phrases detected in website content"
});

}


// TECHNICAL SIGNALS

if(hiddenElements > 10){

risks.push({
element:"DOM Behaviour",
rule:"Large number of hidden elements",
severity:"Medium",
category:"Technical Signals",
reason:"Hidden elements may indicate cloaking or malicious scripts"
});

}

if(iframeCount > 5){

risks.push({
element:"Iframe Behaviour",
rule:"Multiple iframes detected",
severity:"Medium",
category:"Security Signals",
reason:"Phishing websites often embed external pages through iframes"
});

}


// REDIRECT SIGNAL

if(redirects){

risks.push({
element:"URL Behaviour",
rule:"URL redirect detected",
severity:"Low",
category:"Technical Signals",
reason:"Redirect chains can hide the final destination"
});

}


// FALLBACK

if(risks.length === 0){

risks.push({
element:"Overall Assessment",
rule:"No obvious fraud signals",
severity:"Low",
category:"General",
reason:"Automated scan did not detect suspicious patterns"
});

}

return risks;

}

module.exports = generateRiskSignals;