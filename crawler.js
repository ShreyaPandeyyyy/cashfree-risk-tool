const axios = require("axios");
const cheerio = require("cheerio");

async function crawlWebsite(url) {

try {

// -----------------------------
// ENSURE URL HAS PROTOCOL
// -----------------------------

if (!url.startsWith("http")) {
url = "https://" + url;
}


// -----------------------------
// FETCH WEBSITE
// -----------------------------

const response = await axios.get(url,{
timeout:20000,
maxRedirects:5,
validateStatus:()=>true,
headers:{
"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
"Accept-Language":"en-US,en;q=0.9",
"Connection":"keep-alive"
}
});

const html = typeof response.data === "string" ? response.data : "";

console.log("HTML LENGTH:",html.length);

const $ = cheerio.load(html);

const textContent = $("body").text().toLowerCase();

const hostname = new URL(url).hostname;


// -----------------------------
// META DESCRIPTION
// -----------------------------

const metaDescription =
$('meta[name="description"]').attr("content") || null;


// -----------------------------
// EMAIL DETECTION
// -----------------------------

const emailRegex = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
const emails = html.match(emailRegex) || [];


// -----------------------------
// PHONE DETECTION
// -----------------------------

const phoneRegex = /(\+?\d[\d\s\-]{7,}\d)/g;
const phones = html.match(phoneRegex) || [];


// -----------------------------
// LINK ANALYSIS
// -----------------------------

let totalLinks = 0;
let externalLinks = 0;

$("a").each((i,el)=>{

const href = $(el).attr("href");

if(!href) return;

totalLinks++;

if(href.startsWith("http") && !href.includes(hostname)){
externalLinks++;
}

});


// -----------------------------
// SOCIAL MEDIA LINKS
// -----------------------------

const socialLinks = [];

$("a").each((i,el)=>{

const href = $(el).attr("href") || "";

if(
href.includes("facebook.com") ||
href.includes("instagram.com") ||
href.includes("twitter.com") ||
href.includes("linkedin.com")
){
socialLinks.push(href);
}

});


// -----------------------------
// PRIVACY POLICY DETECTION
// -----------------------------

let hasPrivacyPolicy = false;

$("a").each((i,el)=>{

const text = ($(el).text() || "").toLowerCase();
const href = ($(el).attr("href") || "").toLowerCase();

if(
text.includes("privacy") ||
href.includes("privacy")
){
hasPrivacyPolicy = true;
}

});


// -----------------------------
// TERMS DETECTION
// -----------------------------

let hasTerms = false;

$("a").each((i,el)=>{

const text = ($(el).text() || "").toLowerCase();
const href = ($(el).attr("href") || "").toLowerCase();

if(
text.includes("terms") ||
href.includes("terms")
){
hasTerms = true;
}

});


// -----------------------------
// LOGIN FORMS
// -----------------------------

let loginForms = 0;

$("form").each((i,el)=>{

const txt = $(el).text().toLowerCase();

if(
txt.includes("login") ||
txt.includes("password") ||
txt.includes("signin")
){
loginForms++;
}

});


// -----------------------------
// PAYMENT SIGNALS
// -----------------------------

const paymentKeywords = [
"payment",
"checkout",
"credit card",
"debit card",
"upi",
"pay now"
];

let paymentSignals = 0;

paymentKeywords.forEach(k=>{
if(textContent.includes(k)){
paymentSignals++;
}
});


// -----------------------------
// SUSPICIOUS KEYWORDS
// -----------------------------

const suspiciousWords = [
"100% free",
"guaranteed profit",
"instant money",
"no risk",
"earn fast"
];

let suspiciousSignals = 0;

suspiciousWords.forEach(w=>{
if(textContent.includes(w)){
suspiciousSignals++;
}
});


// -----------------------------
// IFRAME DETECTION
// -----------------------------

const iframeCount = $("iframe").length;


// -----------------------------
// HIDDEN ELEMENT DETECTION
// -----------------------------

let hiddenElements = 0;

$("*").each((i,el)=>{

const style = $(el).attr("style") || "";

if(
style.includes("display:none") ||
style.includes("visibility:hidden")
){
hiddenElements++;
}

});


// -----------------------------
// DOMAIN AGE CHECK
// -----------------------------

let domainAgeDays = null;

try{

const domain = hostname;

const whois = await axios.get(
`https://api.api-ninjas.com/v1/whois?domain=${domain}`,
{
headers:{ "X-Api-Key":"demo" },
timeout:5000
}
);

if(whois.data && whois.data.creation_date){

const created = new Date(whois.data.creation_date);
const now = new Date();

if(!isNaN(created)){
domainAgeDays = Math.floor((now-created)/(1000*60*60*24));
}

}

}catch(e){

domainAgeDays = null;

}


// -----------------------------
// SUSPICIOUS TLD
// -----------------------------

const suspiciousTLDs = [
".xyz",
".top",
".loan",
".click",
".buzz",
".gq"
];

const suspiciousTLD = suspiciousTLDs.some(tld =>
hostname.endsWith(tld)
);


// -----------------------------
// REDIRECT CHECK
// -----------------------------

let redirects = false;

try{

const finalUrl = response.request?.res?.responseUrl;

if(finalUrl && finalUrl !== url){
redirects = true;
}

}catch(e){}


// -----------------------------
// RETURN DATA
// -----------------------------

return {

url,
emails,
phones,
totalLinks,
externalLinks,
loginForms,
paymentSignals,
suspiciousSignals,
iframeCount,
hiddenElements,
domainAgeDays,
suspiciousTLD,
redirects,

metaDescription,
socialLinks,
hasPrivacyPolicy,
hasTerms

};

}catch(err){

console.error("Crawler error:",err.message);

return{

url,
emails:[],
phones:[],
totalLinks:0,
externalLinks:0,
loginForms:0,
paymentSignals:0,
suspiciousSignals:0,
iframeCount:0,
hiddenElements:0,
domainAgeDays:null,
suspiciousTLD:false,
redirects:false,

metaDescription:null,
socialLinks:[],
hasPrivacyPolicy:false,
hasTerms:false

};

}

}

module.exports = crawlWebsite;