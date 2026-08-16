(function(){
  "use strict";

  const BUILD = {
    version: "v3.55.0",
    name: "URL Intelligence Expansion",
    privacy: "offline-first engine / local QR decoder path / no runtime CDN dependency",
  };

  const $ = (id) => document.getElementById(id);
  const els = {
    input: $("targetInput"), scanButton: $("scanButton"), detectedInputType: $("detectedInputType"), riskLabel: $("riskLabel"), scoreValue: $("scoreValue"), summaryText: $("summaryText"),
    trueTarget: $("trueTarget"), signalCount: $("signalCount"), nextStep: $("nextStep"), evidenceList: $("evidenceList"), technicalList: $("technicalList"),
    caseNotes: $("caseNotes"), saveCaseButton: $("saveCaseButton"), clearHistoryButton: $("clearHistoryButton"), clearAllLocalDataButton: $("clearAllLocalDataButton"), historyList: $("historyList"), historyStatus: $("historyStatus"),
    scanMode: $("scanMode"), scanModeNote: $("scanModeNote"), rootDomain: $("rootDomain"), rootDomainNote: $("rootDomainNote"),
    confidenceLabel: $("confidenceLabel"), confidenceNote: $("confidenceNote"), safeMove: $("safeMove"), safeMoveNote: $("safeMoveNote"),
    explainStatus: $("explainStatus"), explainSummary: $("explainSummary"), trustStatus: $("trustStatus"), trustTrail: $("trustTrail"),
    threatStatus: $("threatStatus"), threatStory: $("threatStory"), timelineStatus: $("timelineStatus"), timelineList: $("timelineList"),
    learningStatus: $("learningStatus"), learningText: $("learningText"), onlinePreview: $("onlinePreview"),
    severityMix: $("severityMix"), severityNote: $("severityNote"), decisionStatus: $("decisionStatus"), decisionList: $("decisionList"), heatFill: $("heatFill"), heatLabel: $("heatLabel"), primaryTrigger: $("primaryTrigger"), laneQuality: $("laneQuality"), evidenceStrength: $("evidenceStrength"), confidenceBrief: $("confidenceBrief"), whyScore: $("whyScore"), scanMemory: $("scanMemory"), compareLast: $("compareLast"), actionTitle: $("actionTitle"), actionText: $("actionText"), whyMatterTitle: $("whyMatterTitle"), whyMatterText: $("whyMatterText"), safetyTitle: $("safetyTitle"), safetyText: $("safetyText"), inputTypeLabel: $("inputTypeLabel"), reportTimestamp: $("reportTimestamp"), anatomyStatus: $("anatomyStatus"), anatomyProtocol: $("anatomyProtocol"), anatomyHost: $("anatomyHost"), anatomyRoot: $("anatomyRoot"), anatomyPath: $("anatomyPath"), anatomyQuery: $("anatomyQuery"), anatomyTokens: $("anatomyTokens"), anatomyNote: $("anatomyNote"), copyReportButton: $("copyReportButton"), copySummaryButton: $("copySummaryButton"), copyCasePacketButton: $("copyCasePacketButton"), downloadCaseTextButton: $("downloadCaseTextButton"), downloadCasePacketButton: $("downloadCasePacketButton"), explainVerdictButton: $("explainVerdictButton"), copyStatus: $("copyStatus"), userViewButton: $("userViewButton"), analystViewButton: $("analystViewButton"), activeAudienceMode: $("activeAudienceMode"), reportDepthNote: $("reportDepthNote"), analystBriefList: $("analystBriefList"), analystBriefStatus: $("analystBriefStatus"), qrStartButton: $("qrStartButton"), qrStopButton: $("qrStopButton"), qrStatus: $("qrStatus"), qrCameraPanel: $("qrCameraPanel"), qrVideo: $("qrVideo"), memoryDashboardStatus: $("memoryDashboardStatus"), memoryTotalScans: $("memoryTotalScans"), memoryRootCount: $("memoryRootCount"), memoryFamilyCount: $("memoryFamilyCount"), memoryRootList: $("memoryRootList"), memoryFamilyList: $("memoryFamilyList"), copyMemorySummaryButton: $("copyMemorySummaryButton"), downloadMemoryJsonButton: $("downloadMemoryJsonButton"), clearPatternMemoryButton: $("clearPatternMemoryButton"), memoryDashboardNote: $("memoryDashboardNote"), onlineConsentStatus: $("onlineConsentStatus"), onlineConsentDetail: $("onlineConsentDetail"), enableOnlineConsentButton: $("enableOnlineConsentButton"), revokeOnlineConsentButton: $("revokeOnlineConsentButton"), onlineScopeList: $("onlineScopeList"), onlinePrivacyList: $("onlinePrivacyList"), onlineRunPreviewButton: $("onlineRunPreviewButton"), onlineLookupLinksButton: $("onlineLookupLinksButton"), onlineRdapLookupButton: $("onlineRdapLookupButton"), onlineRdapStatus: $("onlineRdapStatus"), onlineRdapResult: $("onlineRdapResult"), onlineArchitectureNote: $("onlineArchitectureNote"), onlineFindingsNotes: $("onlineFindingsNotes"), saveOnlineFindingsButton: $("saveOnlineFindingsButton"), clearOnlineFindingsButton: $("clearOnlineFindingsButton"), onlineFindingsStatus: $("onlineFindingsStatus"), onlineProviderSlotList: $("onlineProviderSlotList"), onlineReadinessList: $("onlineReadinessList"), onlineReadinessStatus: $("onlineReadinessStatus")
  };

  const HISTORY_KEY = "proxuma-it-risk-score-cases-v2";
  const LAST_SCAN_KEY = "proxuma-it-last-scan-v2";
  const PATTERN_MEMORY_KEY = "proxuma-it-local-pattern-memory-v1";
  const ONLINE_CONSENT_KEY = "proxuma-it-online-consent-v1";
  const ONLINE_FINDINGS_KEY = "proxuma-it-online-findings-notes-v1";
  let lastReport = null;
  let audienceView = "user";
  let qrStream = null;
  let qrDetector = null;
  let qrScanLoopActive = false;
  let qrDecoderMode = "native";
  let qrCanvas = null;
  let qrCanvasContext = null;
  let latestRdapSummary = null;

  function formatReportTime(date){
    try {
      return (date || new Date()).toLocaleString([], {
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit"
      });
    } catch (e) {
      return (date || new Date()).toLocaleString();
    }
  }

  function formatCompactReportTime(date){
    const d = date || new Date();
    try {
      const datePart = d.toLocaleDateString([], { month: "short", day: "numeric" });
      const timePart = d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
      return datePart + "\n" + timePart;
    } catch (e) {
      return formatReportTime(d).replace(/,\s*\d{4},?\s*/, "\n");
    }
  }

  const shorteners = new Set(["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","cutt.ly","rebrand.ly","lnkd.in","s.id","rb.gy","shorturl.at","short.io","tiny.cc","t.ly","bitly.com","trib.al","lnk.to","qrco.de","buff.ly","soo.gd","bl.ink","shorte.st","snip.ly","taplink.cc","linktr.ee","beacons.ai","campsite.bio","bio.site","solo.to"]);
  const relayRoots = new Set(["google.com","facebook.com","linkedin.com","twitter.com","x.com","youtube.com","mandrillapp.com","sendgrid.net","mailchimp.com","list-manage.com","constantcontact.com","hubspotlinks.com","clickdimensions.com","salesforce.com","sfmc-content.com","emltrk.com","ct.sendgrid.net","urldefense.com","proofpoint.com","safelinks.protection.outlook.com"]);
  const relayPathHints = ["/url", "/l.php", "/lnk", "/track", "/track/click", "/click", "/redirect", "/redir", "/r/", "/u/", "/link", "/links", "/safe-link", "/safelink"];
  const trustedRoots = new Set([
    "rbcroyalbank.com","rbc.com","royalbank.com","rbcbank.com","rbcdirectinvesting.com",
    "td.com","tdcanadatrust.com","scotiabank.com","bmo.com","cibc.com","nationalbank.com","nbc.ca","desjardins.com","tangerine.ca",
    "bankofamerica.com","bofa.com","chase.com","jpmorganchase.com","wellsfargo.com","citi.com","citibank.com","capitalone.com","pnc.com","truist.com","usbank.com","americanexpress.com","amex.com","discover.com","ally.com","schwab.com","fidelity.com","navyfederal.org",
    "canada.ca","ontario.ca","quebec.ca","servicecanada.gc.ca","github.com","vercel.com","vercel.app","google.com","google.ca","gmail.com","share.google","microsoft.com","microsoftonline.com","msauth.net","live.com","office.com","office365.com","outlook.com","onedrive.live.com","apple.com","icloud.com","amazon.com","amazon.ca","paypal.com","stripe.com","squareup.com","cash.app","venmo.com","zellepay.com","wise.com","westernunion.com","interac.ca","canadapost-postescanada.ca","canadapost.ca","ups.com","fedex.com","dhl.com","rogers.com","bell.ca","telus.com","fido.ca","koodomobile.com","virginplus.ca","freedommobile.ca","facebook.com","instagram.com","tiktok.com","x.com","twitter.com","linkedin.com","ebay.com","etsy.com","walmart.com","walmart.ca","dropbox.com","norton.com","mcafee.com","equifax.com","transunion.com","coinbase.com","binance.com","kraken.com","wealthsimple.com"
  ]);
  const brandFamilies = [
    {name:"RBC / Royal Bank", aliases:["rbc","royalbank","royal-bank","royal bank"], roots:["rbcroyalbank.com","rbc.com","royalbank.com","rbcbank.com","rbcdirectinvesting.com"]},
    {name:"TD / TD Bank", aliases:["td","tdbank","td-bank","td canada trust","easyweb"], roots:["td.com","tdcanadatrust.com"]},
    {name:"Scotiabank", aliases:["scotia","scotiabank"], roots:["scotiabank.com"]},
    {name:"BMO / Bank of Montreal", aliases:["bmo","bankofmontreal","bank-of-montreal","bank of montreal"], roots:["bmo.com"]},
    {name:"CIBC", aliases:["cibc"], roots:["cibc.com"]},
    {name:"National Bank of Canada", aliases:["nationalbank","national-bank","national bank","nbc"], roots:["nationalbank.com","nbc.ca"]},
    {name:"Desjardins", aliases:["desjardins"], roots:["desjardins.com"]},
    {name:"Tangerine", aliases:["tangerine"], roots:["tangerine.ca"]},
    {name:"Bank of America", aliases:["bankofamerica","bank-of-america","bank of america","bofa"], roots:["bankofamerica.com","bofa.com"]},
    {name:"Chase / JPMorgan Chase", aliases:["chase","jpmorgan","jp-morgan","jpmorganchase"], roots:["chase.com","jpmorganchase.com"]},
    {name:"Wells Fargo", aliases:["wellsfargo","wells-fargo","wells fargo"], roots:["wellsfargo.com"]},
    {name:"Citi / Citibank", aliases:["citi","citibank"], roots:["citi.com","citibank.com"]},
    {name:"Capital One", aliases:["capitalone","capital-one","capital one"], roots:["capitalone.com"]},
    {name:"PNC Bank", aliases:["pnc","pnc-bank","pnc bank"], roots:["pnc.com"]},
    {name:"Truist", aliases:["truist"], roots:["truist.com"]},
    {name:"U.S. Bank", aliases:["usbank","us-bank","u.s. bank","us bank"], roots:["usbank.com"]},
    {name:"American Express", aliases:["americanexpress","american-express","american express","amex"], roots:["americanexpress.com","amex.com"]},
    {name:"Discover", aliases:["discover","discovercard","discover-card","discover card"], roots:["discover.com"]},
    {name:"Ally Bank", aliases:["ally","allybank","ally-bank","ally bank"], roots:["ally.com"]},
    {name:"Charles Schwab", aliases:["schwab","charlesschwab","charles-schwab","charles schwab"], roots:["schwab.com"]},
    {name:"Fidelity", aliases:["fidelity","fidelityinvestments","fidelity-investments","fidelity investments"], roots:["fidelity.com"]},
    {name:"Navy Federal Credit Union", aliases:["navyfederal","navy-federal","navy federal","nfcu"], roots:["navyfederal.org"]},
    {name:"PayPal", aliases:["paypal","pay-pal"], roots:["paypal.com"]},
    {name:"Interac", aliases:["interac","etransfer","e-transfer","interac e transfer","interac-transfer"], roots:["interac.ca"]},
    {name:"Canada Revenue Agency / Government of Canada", aliases:["cra","canada revenue agency","revenue canada","service canada","government of canada","gc ca","canada benefits"], roots:["canada.ca","servicecanada.gc.ca"]},
    {name:"Ontario Government", aliases:["ontario","serviceontario","service ontario"], roots:["ontario.ca"]},
    {name:"Quebec Government", aliases:["quebec","revenue quebec","revenu quebec"], roots:["quebec.ca"]},
    {name:"Canada Post", aliases:["canadapost","canada-post","canada post","postescanada","postes canada"], roots:["canadapost-postescanada.ca","canadapost.ca"]},
    {name:"UPS", aliases:["ups","ups tracking","ups delivery"], roots:["ups.com"]},
    {name:"FedEx", aliases:["fedex","fed-ex","fed ex"], roots:["fedex.com"]},
    {name:"DHL", aliases:["dhl","dhl express"], roots:["dhl.com"]},
    {name:"Rogers", aliases:["rogers","rogers wireless"], roots:["rogers.com"]},
    {name:"Bell", aliases:["bell","bell mobility","mybell"], roots:["bell.ca"]},
    {name:"TELUS", aliases:["telus","mytelus"], roots:["telus.com"]},
    {name:"Fido", aliases:["fido","fido mobile"], roots:["fido.ca"]},
    {name:"Koodo", aliases:["koodo","koodo mobile"], roots:["koodomobile.com"]},
    {name:"Virgin Plus", aliases:["virginplus","virgin-plus","virgin plus"], roots:["virginplus.ca"]},
    {name:"Freedom Mobile", aliases:["freedommobile","freedom-mobile","freedom mobile"], roots:["freedommobile.ca"]},
    {name:"Microsoft", aliases:["microsoft","office365","outlook","ms-login","microsoftonline"], roots:["microsoft.com","microsoftonline.com","msauth.net","live.com","office.com","office365.com","outlook.com"]},
    {name:"Apple", aliases:["apple","icloud","appleid"], roots:["apple.com","icloud.com"]},
    {name:"Google", aliases:["google","gmail","gdrive"], roots:["google.com","gmail.com","google.ca","share.google"]},
    {name:"Amazon", aliases:["amazon","prime"], roots:["amazon.com","amazon.ca"]},
    {name:"Coinbase", aliases:["coinbase","coin-base","coinbase wallet"], roots:["coinbase.com"]},
    {name:"Binance", aliases:["binance","binance login"], roots:["binance.com"]},
    {name:"Kraken", aliases:["kraken","kraken crypto"], roots:["kraken.com"]},
    {name:"Wealthsimple", aliases:["wealthsimple","wealth simple"], roots:["wealthsimple.com"]},
    {name:"Stripe", aliases:["stripe","stripe account","stripe payment"], roots:["stripe.com"]},
    {name:"Square / Block", aliases:["square","squareup","block payments","cash app","cashapp"], roots:["squareup.com","cash.app"]},
    {name:"Venmo", aliases:["venmo"], roots:["venmo.com"]},
    {name:"Zelle", aliases:["zelle","zellepay"], roots:["zellepay.com"]},
    {name:"Wise", aliases:["wise","wise transfer","transferwise"], roots:["wise.com"]},
    {name:"Western Union", aliases:["westernunion","western-union","western union"], roots:["westernunion.com"]},
    {name:"OneDrive / Microsoft Cloud", aliases:["onedrive","one-drive","one drive","sharepoint","office document"], roots:["onedrive.live.com","microsoft.com","microsoftonline.com","office.com","office365.com"]},
    {name:"Dropbox", aliases:["dropbox","drop-box"], roots:["dropbox.com"]},
    {name:"Facebook / Meta", aliases:["facebook","meta","fb security","facebook security"], roots:["facebook.com"]},
    {name:"Instagram", aliases:["instagram","insta"], roots:["instagram.com"]},
    {name:"TikTok", aliases:["tiktok","tik-tok","tik tok"], roots:["tiktok.com"]},
    {name:"X / Twitter", aliases:["twitter","x account","tweet"], roots:["x.com","twitter.com"]},
    {name:"LinkedIn", aliases:["linkedin","linked-in","linked in"], roots:["linkedin.com"]},
    {name:"eBay", aliases:["ebay","e-bay"], roots:["ebay.com"]},
    {name:"Etsy", aliases:["etsy"], roots:["etsy.com"]},
    {name:"Walmart", aliases:["walmart","wal-mart"], roots:["walmart.com","walmart.ca"]},
    {name:"Norton", aliases:["norton","norton lifelock","lifelock"], roots:["norton.com"]},
    {name:"McAfee", aliases:["mcafee","mc-afee"], roots:["mcafee.com"]},
    {name:"Equifax", aliases:["equifax","equifax canada"], roots:["equifax.com"]},
    {name:"TransUnion", aliases:["transunion","trans-union","trans union"], roots:["transunion.com"]}
  ];
  const pressureWords = ["urgent","verify","account","suspend","locked","unlock","confirm","password","security","secure","reward","prize","winner","refund","invoice","payment","wallet","banking","login","signin","sign-in","update","limited","final","action-required","delivery","parcel","tracking","benefit","benefits","tax","deposit"];
  const sensitiveLookalikeWords = new Set(["login","signin","secure","security","verify","account","password","payment","wallet","banking","reset","unlock","confirm"]);
  const riskyTlds = new Set(["zip","mov","top","xyz","click","quest","rest","country","stream","download","loan","support"]);
  const riskyExtensions = [".exe",".scr",".bat",".cmd",".cpl",".hta",".js",".jse",".vbs",".vbe",".wsf",".wsh",".msi",".msp",".apk",".jar",".ps1",".psm1",".psd1",".reg",".lnk",".iso",".img",".dmg",".pkg",".deb",".rpm",".appimage"];
  const compressedDeliveryExtensions = [".zip",".rar",".7z",".tar",".gz",".tgz",".bz2",".xz"];
  const downloadTrapWords = new Set(["download","downloads","setup","installer","install","update","upgrade","patch","driver","security-update","secure-update","verify-update","invoice-download","statement-download","file","attachment","document","payload","release","run","open","launch"]);
  const executableParamNames = new Set(["file","filename","download","dl","attachment","document","doc","package","pkg","installer","setup","update","payload","app","apk","exe"]);
  const harmlessFileBaits = [".pdf",".doc",".docx",".xls",".xlsx",".jpg",".jpeg",".png",".txt",".invoice",".receipt",".statement"];
  const redirectParamNames = new Set(["redirect","redir","url","u","target","next","continue","return","returnurl","return_to","dest","destination","goto","to","link","r"]);
  const credentialParamNames = new Set(["password","pass","passwd","pwd","token","auth","session","sessionid","otp","2fa","mfa","code","pin","login","signin","account","verify"]);
  const sensitiveWorkflowWords = new Set(["login","signin","signon","verify","account","password","payment","wallet","banking","secure","security","reset","unlock","confirm","update"]);
  const unicodeLookalikes = /[а-яА-ЯёЁіІїЇєЄαβγροсѕӏ]/;
  const qrStructuredPrefixes = ["wifi:", "mailto:", "matmsg:", "smsto:", "sms:", "tel:", "geo:", "begin:vcard", "mecard:", "otpauth:"];
  const highValueWorkflowWords = new Set(["login","signin","signon","verify","verification","account","password","payment","wallet","banking","secure","security","reset","unlock","confirm","update","support","alert","delivery","parcel","tracking","benefit","benefits","tax","refund","deposit","transfer","etransfer","e-transfer"]);
  const suspiciousPathFolders = new Set(["wp-content","wp-admin","uploads","includes","assets","static","cdn","cache","tmp","temp","public","files","download","downloads","docs","documents","account","accounts","secure","security","verify","verification","login","signin","auth","portal","billing","payment"]);
  const suspiciousFileNames = new Set(["login.html","signin.html","verify.html","verification.html","account.html","secure.html","security.html","payment.html","wallet.html","update.html","confirm.html","index.php","login.php","verify.php","account.php","secure.php","payment.php"]);
  const credentialIntentWords = new Set(["login","signin","sign-in","auth","authenticate","account","secure","security","verify","verification","validate","confirm","password","passwd","pwd","reset","unlock","recover","recovery","otp","2fa","mfa","pin","code","token","session","sso","credential","credentials"]);
  const credentialCollectionWords = new Set(["submit","form","portal","access","continue","update","confirm","validate","recover","reset","unlock","authorize","authorization","claim","redeem"]);
  const credentialFinancialWords = new Set(["payment","billing","wallet","banking","bank","etransfer","e-transfer","interac","refund","invoice","tax","deposit","transfer","card","credit","debit"]);
  const credentialPressureWords = new Set(["urgent","locked","suspend","suspended","unusual","alert","limited","final","expire","expired","immediate","required","action-required"]);
  const callbackIntentWords = new Set(["call","callback","phone","telephone","hotline","support","agent","representative","desk","helpline","contact","speak","verify","confirm","unlock","refund","billing","payment","bank","banking","card","delivery","parcel","ticket","fine","tax","benefit","benefits","account","security","fraud","crypto","wallet","giftcard","gift-card"]);
  const callbackPressureWords = new Set(["urgent","immediately","now","today","final","limited","expire","expired","suspend","suspended","locked","unusual","warning","alert","required","avoid","penalty","charge","charged","arrest","legal","collections"]);
  const callbackSensitiveWords = new Set(["password","pin","otp","2fa","mfa","code","token","card","credit","debit","banking","wallet","crypto","giftcard","gift-card","interac","etransfer","e-transfer","refund","invoice","tax","payment","account","login","verify"]);
  const attachmentFileIntentWords = new Set(["attachment","attached","enclosed","file","document","doc","pdf","invoice","statement","receipt","remittance","payment","purchase","order","po","quote","quotation","contract","agreement","forms","form","secure-document","shared-file","download-file","view-file","open-file","document-center","file-share","filedrop"]);
  const attachmentActionWords = new Set(["open","view","download","review","sign","approve","authorize","access","retrieve","print","read","confirm","validate","accept","release","unlock"]);
  const attachmentCloudBrandWords = new Set(["docusign","docu-sign","adobe-sign","adobesign","onedrive","one-drive","sharepoint","dropbox","google-drive","gdrive","drive","box","wetransfer","we-transfer","icloud","office365","microsoft365","securemail","secure-message","encrypted-message"]);
  const attachmentMacroWords = new Set(["enable-macros","enable-content","enable-editing","protected-view","content-disabled","macro","macros","allow-editing","allow-content","disable-protected-view"]);
  const attachmentPressureWords = new Set(["urgent","immediate","today","final","overdue","past-due","limited","expire","expired","required","action-required","penalty","collections","legal","suspend","locked","release","settlement","refund","customs","delivery","tax"]);
  const paymentInvoiceIntentWords = new Set(["invoice","billing","bill","payment","pay","paid","charge","charged","transaction","purchase","receipt","statement","subscription","renewal","refund","refunds","rebate","credit","debit","card","balance","overdue","past-due","amount-due","payment-method","method-of-payment","accounting","accounts-payable","remittance","interac","etransfer","e-transfer","wire-transfer","bank-transfer","auto-pay","autopay","preauthorized","pre-authorized","unauthorized-charge","unknown-charge","failed-payment","payment-failed","declined","chargeback"]);
  const paymentActionWords = new Set(["review","confirm","verify","update","validate","authorize","approve","pay","settle","release","claim","accept","open","view","download","resolve","reactivate","restore","unlock","cancel","dispute"]);
  const paymentPressureWords = new Set(["urgent","immediate","today","final","overdue","past-due","late","limited","expire","expired","required","action-required","penalty","collections","legal","suspend","suspended","locked","avoid","deadline","last-notice","final-notice"]);
  const urgencyPressureWords = new Set(["urgent","immediate","immediately","now","today","tonight","final","final-notice","last-notice","limited-time","limited","deadline","expires","expire","expired","within-24-hours","24-hours","48-hours","action-required","required-now","act-now","respond-now","verify-now","confirm-now","avoid-closure","avoid-suspension","suspended","suspend","locked","blocked","penalty","fine","collections","legal-action","last-chance","do-not-ignore"]);
  const urgencyActionWords = new Set(["verify","confirm","update","validate","respond","act","click","open","view","download","call","contact","pay","settle","claim","release","unlock","restore","reactivate","complete","submit","provide","authorize","approve"]);
  const urgencySensitiveWords = new Set(["account","login","password","pin","otp","code","card","bank","banking","payment","wallet","crypto","identity","id","passport","sin","ssn","address","phone","email","document","invoice","delivery","benefit","tax","refund"]);
  const authorityVoiceIdentityWords = new Set(["department","support-team","security-team","fraud-department","fraud-team","billing-department","accounting","collections","compliance","legal-department","legal-team","review-team","verification-team","risk-department","administrator","admin","officer","agent","representative","case-manager","claims-department","hr","payroll","recruitment-team","government-office","tax-office","revenue-agency","customs-office","carrier-team","delivery-office"]);
  const authorityVoiceClaimWords = new Set(["official","official-notice","notice","case","case-id","reference","reference-number","ticket","claim","claim-id","file-number","record","department-notice","review","audit","investigation","compliance-review","security-review","account-review","manual-review","verification-required","approved","pre-approved","selected","authorized","authorization","certified","validated"]);
  const authorityVoiceActionWords = new Set(["verify","confirm","validate","submit","provide","complete","respond","reply","contact","call","open","view","download","sign","approve","authorize","release","claim","settle","pay","update","review"]);
  const authorityVoiceSensitiveWords = new Set(["password","otp","pin","code","token","account","login","card","bank","banking","payment","wallet","crypto","sin","ssn","passport","license","licence","id","identity","address","phone","email","document","invoice","tax","benefit","payroll"]);
  const mfaOtpIntentWords = new Set(["otp","one-time-code","one-time-password","verification-code","security-code","2fa","two-factor","multi-factor","mfa","authenticator","authentication-code","login-code","signin-code","sign-in-code","sms-code","text-code","push-notification","push-approval","approve-login","approval-request","device-code","backup-code","recovery-code","code","token"]);
  const mfaOtpActionWords = new Set(["send","share","enter","provide","submit","confirm","verify","validate","approve","authorize","allow","accept","tap","click","reply","forward","copy","paste","complete","continue","unlock","restore","recover"]);
  const mfaOtpContextWords = new Set(["account","login","signin","sign-in","password","bank","banking","payment","wallet","crypto","email","icloud","microsoft","google","paypal","interac","etransfer","e-transfer","admin","work","payroll","support","security","fraud","device","session"]);
  const mfaOtpPressureWords = new Set(["urgent","immediate","now","expires","expire","expired","within","minutes","final","suspended","locked","blocked","unauthorized","fraud","security-alert","required","action-required","do-not-ignore"]);
  const accountRecoveryIntentWords = new Set(["account-recovery","recover-account","recovery-link","password-reset","reset-password","password-change","change-password","email-change","change-email","phone-number-change","device-change","new-device","unknown-device","session-reset","restore-account","reactivate-account","unlock-account","account-unlock","login-reset","security-reset","profile-recovery","identity-confirmation","recover","recovery","reset","restore","reactivate","unlock"]);
  const accountRecoveryActionWords = new Set(["click","open","use","follow","confirm","verify","validate","approve","authorize","allow","accept","complete","continue","submit","provide","enter","update","change","restore","recover","reset","unlock","reactivate","review"]);
  const accountRecoveryContextWords = new Set(["account","login","signin","sign-in","password","email","phone","device","session","profile","security","fraud","bank","banking","payment","wallet","crypto","paypal","interac","microsoft","google","icloud","apple","work","admin","payroll"]);
  const accountRecoveryPressureWords = new Set(["urgent","immediate","now","expires","expire","expired","within","minutes","final","suspended","locked","blocked","unauthorized","fraud","security-alert","required","action-required","do-not-ignore","limited-time","final-notice"]);
  const paymentSensitiveWords = new Set(["card","credit-card","debit-card","cvv","cvc","bank","banking","account","routing","sort-code","password","login","signin","otp","pin","code","interac","etransfer","e-transfer","wallet","crypto","paypal","stripe","square","cashapp","venmo","zelle"]);
  const moneyMovementRailWords = new Set(["interac","etransfer","e-transfer","zelle","venmo","cashapp","cash-app","paypal","wire","wire-transfer","bank-transfer","direct-deposit","deposit","refund-deposit","refund","rebate","claim-payment","accept-payment","receive-payment","send-money","money-transfer","transfer","recipient","payee","sender","remittance","settlement","release-funds","funds-release","payment-rail"]);
  const moneyMovementActionWords = new Set(["accept","claim","receive","send","transfer","deposit","verify","confirm","validate","authorize","approve","release","unlock","update","enter","provide","submit","continue","open","view","cancel","reverse","dispute"]);
  const moneyMovementPressureWords = new Set(["urgent","immediate","today","final","expire","expired","pending","on-hold","held","locked","blocked","failed","declined","unauthorized","unknown","unrecognized","limited","deadline","action-required","security-hold","fraud-alert"]);
  const moneyMovementSensitiveWords = new Set(["bank","banking","account","routing","sort-code","institution-number","transit-number","card","credit-card","debit-card","cvv","cvc","pin","otp","code","password","login","signin","email","phone","identity","id","sin","ssn","address"]);
  const giftPrizeRewardIntentWords = new Set(["gift-card","giftcard","prepaid-card","voucher","reward","rewards","points","loyalty","bonus","prize","winner","won","giveaway","sweepstake","sweepstakes","lottery","raffle","claim-prize","claim-reward","cashback","cash-back","airmiles","aeroplan","scene","pc-optimum","optimum","starbucks-reward","amazon-gift","apple-gift","steam-card","google-play","play-card","itunes","visa-gift","mastercard-gift"]);
  const giftPrizeRewardActionWords = new Set(["claim","redeem","activate","accept","verify","confirm","validate","unlock","release","collect","receive","open","view","continue","complete","submit","provide","enter","pay","purchase","buy","send","upload"]);
  const giftPrizeRewardPressureWords = new Set(["urgent","immediate","today","now","limited","expire","expired","expires","final","last-chance","selected","exclusive","guaranteed","pending","on-hold","held","action-required","deadline","winner","congratulations"]);
  const giftPrizeRewardSensitiveWords = new Set(["card","gift-card","prepaid-card","voucher-code","pin","code","claim-code","security-code","barcode","receipt","photo","email","phone","address","identity","id","bank","payment","wallet","crypto","password","login","account"]);
  const subscriptionRenewalIntentWords = new Set(["subscription","renewal","renew","plan","membership","member","premium","trial","free-trial","billing","payment-method","card-update","update-card","auto-renew","autorenew","auto-renewal","autopay","recurring","monthly","annual","yearly","storage","cloud-storage","mailbox","domain-renewal","domain-expiry","hosting","license","licence","antivirus","vpn","streaming","netflix","spotify","icloud","microsoft-365","office-365","google-one","dropbox","adobe","norton","mcafee","prime"]);
  const subscriptionRenewalActionWords = new Set(["renew","reactivate","restore","update","confirm","verify","validate","pay","settle","resolve","continue","complete","submit","provide","enter","open","view","cancel","avoid","keep","upgrade","unlock"]);
  const subscriptionRenewalPressureWords = new Set(["urgent","immediate","today","now","final","last-notice","expire","expires","expired","expiring","deadline","suspend","suspended","cancel","cancelled","canceled","termination","terminated","locked","blocked","failed","declined","overdue","past-due","action-required","limited","avoid-loss"]);
  const subscriptionRenewalSensitiveWords = new Set(["card","credit-card","debit-card","cvv","cvc","bank","payment","billing","account","login","password","otp","pin","code","email","phone","address","identity","id","domain","license-key","licence-key"]);
  const deliveryIntentWords = new Set(["delivery","deliver","package","parcel","shipment","shipping","tracking","track","courier","post","postal","mail","redelivery","re-delivery","customs","duty","duties","import","clearance","warehouse","depot","address","undelivered","missed-delivery","delivery-failed","failed-delivery","held-package","package-held","label","pickup","pick-up","dispatch","driver","route","signature","last-mile","sortation","fulfillment","fulfilment","recipient","delivery-window"]);
  const deliveryCarrierWords = new Set(["ups","fedex","dhl","usps","canada-post","canadapost","royal-mail","purolator","amazon","dpd","hermes","evri","auspost","postnl","courier","postal-service","express","ontrac","lasership","gls","yodel","parcelforce","aramex"]);
  const deliveryActionWords = new Set(["confirm","verify","update","correct","pay","settle","release","schedule","reschedule","book","claim","open","view","track","continue","complete","validate","provide","submit","choose","authorize","authorise","unlock","clear"]);
  const deliveryPressureWords = new Set(["urgent","today","immediate","final","last-notice","expire","expired","hold","held","pending","failed","undelivered","returned","return-to-sender","storage-fee","fee","customs-fee","duty-fee","avoid","suspend","blocked","required","action-required","attempted","missed","delayed","delay","detained","clearance-required"]);
  const deliverySensitiveWords = new Set(["address","phone","card","credit-card","debit-card","cvv","bank","payment","fee","customs","duty","login","account","otp","pin","code","password","identity","id","passport","signature","recipient","unit-number","apartment"]);
  const deliveryFeeWords = new Set(["delivery-fee","redelivery-fee","shipping-fee","customs-fee","duty-fee","clearance-fee","storage-fee","release-fee","handling-fee","import-tax","border-fee","small-fee","unpaid-fee","postage-due"]);
  const deliveryPortalWords = new Set(["tracking-portal","delivery-portal","secure-tracking","parcel-center","package-center","shipment-center","carrier-portal","redelivery-center","address-correction","delivery-confirmation"]);
  const parkingTollTransitIntentWords = new Set(["parking","park","meter","parking-meter","paybyphone","pay-by-phone","parkmobile","green-p","honkmobile","hangtag","passport-parking","toll","tolls","toll-road","turnpike","407-etr","ezpass","e-zpass","fastrak","sunpass","plate","license-plate","licence-plate","vehicle","violation","citation","ticket","fine","penalty","infraction","transit","fare","fare-card","presto","metrocard","tap-card","bus","train","subway","station","ticketing"]);
  const parkingTollTransitActionWords = new Set(["pay","settle","resolve","appeal","verify","confirm","update","enter","provide","submit","scan","continue","complete","validate","claim","view","open","lookup","search","release","avoid"]);
  const parkingTollTransitPressureWords = new Set(["urgent","immediate","today","final","last-notice","deadline","expire","expired","overdue","late","unpaid","past-due","collections","penalty","fine","tow","towed","impound","suspend","suspended","enforcement","avoid","required","action-required"]);
  const parkingTollTransitSensitiveWords = new Set(["plate","license-plate","licence-plate","vehicle","vin","driver-license","drivers-license","licence","license","address","phone","card","credit-card","debit-card","cvv","bank","payment","fee","account","login","otp","pin","code","identity","id"]);
  const governmentTaxLegalIntentWords = new Set(["government","federal","ministry","department","agency","tax","taxes","tax-refund","refund","rebate","benefit","benefits","deposit","cra","irs","hmrc","revenue","revenue-agency","service-canada","canada-revenue-agency","social-security","medicare","medicaid","cpp","oas","gst","hst","climate-rebate","immigration","passport","visa","permit","work-permit","student-permit","citizenship","license","licence","dmv","mto","court","legal","law","police","rcmp","fine","ticket","citation","warrant","summons","case","audit","assessment","arrears","penalty","violation","overpayment","underpayment","notice-of-assessment"]);
  const governmentActionWords = new Set(["verify","confirm","update","validate","claim","submit","provide","pay","settle","resolve","appeal","download","view","open","complete","continue","respond","unlock","release","reactivate","restore","schedule","book","upload","register","activate","accept","receive","collect","correct","renew","reassess"]);
  const governmentPressureWords = new Set(["urgent","immediate","today","final","last-notice","deadline","expire","expired","required","action-required","penalty","fine","fined","legal","court","warrant","arrest","suspend","suspended","blocked","locked","collections","enforcement","avoid","failure-to-respond","past-due","overdue","eligible","unclaimed","pending","approved","denied","case-opened","case-file","audit","reassessment","garnishment","deportation","removal","hearing"]);
  const governmentSensitiveWords = new Set(["sin","ssn","social-security-number","social-insurance-number","tax-id","taxpayer","passport","driver-license","drivers-license","licence","license","permit","visa","bank","banking","account","direct-deposit","routing","card","credit-card","debit-card","password","login","signin","otp","pin","code","address","phone","identity","id","date-of-birth","dob","biometric","photo-id","document-number"]);
  const fakeSecurityAlertIntentWords = new Set(["security","secure","alert","warning","virus","malware","spyware","trojan","infected","infection","threat","breach","compromised","hacked","unauthorized","unusual","suspicious","account-locked","locked","suspended","blocked","quarantine","firewall","antivirus","defender","support","tech-support","helpdesk","security-center","device","computer","browser","windows","microsoft","apple","icloud","google","chrome","safari","edge"]);
  const fakeSecurityActionWords = new Set(["call","contact","phone","download","install","run","scan","repair","remove","clean","fix","verify","confirm","update","unlock","restore","reactivate","protect","allow","grant","connect","continue","open","click","approve"]);
  const fakeSecurityPressureWords = new Set(["urgent","immediate","now","today","critical","severe","final","last-warning","expire","expired","required","action-required","at-risk","risk","blocked","locked","suspended","avoid","prevent","damage","loss","stolen","exposed"]);
  const fakeSecuritySensitiveWords = new Set(["password","login","account","otp","pin","code","token","bank","banking","card","payment","wallet","crypto","remote-access","remote","anydesk","teamviewer","ultraviewer","screen-share","screenshare","session","device-id","serial"]);
  const jobEmploymentIntentWords = new Set(["job","jobs","career","careers","hiring","hire","recruiter","recruitment","interview","candidate","applicant","application","position","role","offer","job-offer","employment","employee","onboarding","hr","human-resources","payroll","salary","wage","remote-work","work-from-home","wfh","freelance","contract","contractor","training","orientation","background-check","resume","cv","linkedin","indeed","workday","greenhouse","lever","task","tasks","task-job","task-platform","side-hustle","data-entry","virtual-assistant","personal-assistant","mystery-shopper","secret-shopper","product-reviewer","reshipping","package-forwarding","quality-control","warehouse-assistant","remote-assistant","trial-shift"]);
  const jobEmploymentActionWords = new Set(["apply","accept","confirm","verify","complete","submit","upload","download","open","review","schedule","book","reserve","register","start","activate","sign","sign-in","login","reply","contact","message","purchase","buy","deposit","cash","receive","ship","reship","forward","process","onboard","set-up","setup","connect","join"]);
  const jobEmploymentPressureWords = new Set(["urgent","immediate","today","limited","expire","expired","final","selected","shortlisted","approved","guaranteed","no-experience","high-paying","quick","asap","deadline","required","last-step","pre-approved","same-day","daily-pay","instant-pay","easy-money","no-interview","start-now","limited-slots","limited-positions"]);
  const jobEmploymentSensitiveWords = new Set(["ssn","sin","social-security","social-insurance","tax-id","passport","driver-license","drivers-license","licence","license","dob","date-of-birth","bank","banking","direct-deposit","routing","account-number","card","credit-card","debit-card","password","login","otp","pin","code","background-check","identity","id","w-4","i-9","td1","selfie","photo-id","proof-of-address","utility-bill","void-cheque","void-check"]);
  const jobEmploymentMoneyWords = new Set(["check","cheque","cashier-check","cashiers-check","money-order","equipment","equipment-fee","starter-kit","training-fee","processing-fee","application-fee","activation-fee","deposit","reimbursement","advance","gift-card","giftcard","crypto","wire-transfer","zelle","interac","e-transfer","etransfer","payroll","vendor","supplier","laptop","software","prepaid","commission","bonus","task-commission","task-balance","withdrawal","recharge"]);
  const cryptoInvestmentIntentWords = new Set(["crypto","cryptocurrency","bitcoin","btc","ethereum","eth","usdt","tether","stablecoin","wallet","wallets","exchange","binance","coinbase","kraken","metamask","trust-wallet","ledger","trezor","defi","web3","nft","airdrop","token","staking","stake","liquidity","mining","trading","trader","investment","invest","investor","portfolio","profit","profits","returns","yield","dividend","bonus","forex","fx","stock","shares","market","broker","brokerage","binary-options","options","futures"]);
  const cryptoInvestmentActionWords = new Set(["connect","sync","validate","verify","confirm","claim","withdraw","deposit","transfer","send","receive","unlock","recover","restore","activate","approve","authorize","link","import","open","login","sign-in","submit","continue","start","join","register","invest","trade","buy","sell","stake","swap","bridge","mint","redeem"]);
  const cryptoInvestmentPressureWords = new Set(["urgent","immediate","today","limited","expire","expired","final","last-chance","deadline","guaranteed","risk-free","no-risk","exclusive","bonus","double","instant","fast","profit","profits","high-return","high-yield","locked","suspended","frozen","pending","required","action-required"]);
  const cryptoInvestmentSensitiveWords = new Set(["seed","seed-phrase","recovery-phrase","secret-phrase","private-key","wallet-key","keystore","mnemonic","password","passphrase","otp","2fa","mfa","pin","code","wallet","bank","card","credit-card","debit-card","account","login","identity","id","passport","license","licence"]);
  const cryptoInvestmentMoneyWords = new Set(["deposit","withdraw","withdrawal","transfer","wire-transfer","send","fee","gas-fee","network-fee","tax","unlock-fee","release-fee","recovery-fee","commission","profit","returns","yield","roi","bonus","double","triple","guaranteed-return","risk-free","liquidity","mining","staking","trading-bot","bot","copy-trading","signals","pump","presale","airdrop"]);
  const romanceTrustIntentWords = new Set(["love","romance","romantic","relationship","dating","date","dating-site","match","soulmate","fiance","fiancee","husband","wife","widow","widower","military","deployment","doctor","engineer","contractor","oil-rig","overseas","abroad","long-distance","friendship","trust","trust-me","secret","private","lonely","alone","chat","message","telegram","whatsapp","signal","hangouts","google-chat","facebook","instagram","tiktok","snapchat"]);
  const romanceTrustActionWords = new Set(["send","transfer","wire","buy","purchase","pay","help","support","loan","borrow","deposit","release","unlock","receive","claim","open","click","join","move","message","contact","chat","verify","confirm","share","upload","send-photo","video-call"]);
  const romanceTrustPressureWords = new Set(["urgent","emergency","today","now","immediate","please","desperate","stuck","stranded","hospital","surgery","accident","detained","customs","visa","flight","ticket","travel","fee","hotel","rent","food","child","family","sick","dying","danger","promise","secret","do-not-tell","dont-tell","private","trust-me"]);
  const romanceTrustMoneyWords = new Set(["gift-card","giftcard","itunes","apple-card","steam-card","google-play","amazon-card","prepaid","crypto","bitcoin","wallet","cashapp","zelle","venmo","paypal","interac","e-transfer","etransfer","western-union","moneygram","wire-transfer","bank-transfer","fee","customs-fee","travel-fee","visa-fee","medical-bill","hospital-bill","rent","loan","funds","money"]);
  const romanceTrustSensitiveWords = new Set(["photo","private-photo","intimate-photo","video","passport","id","identity","address","phone","bank","card","password","otp","pin","code","account","login","secret","blackmail","expose","leak","nude","personal"]);

  const modernAiEmergencyWords = new Set(["new-number","new-phone","lost-phone","broken-phone","do-not-call","dont-call","cannot-talk","cant-talk","text-only","voice-clone","deepfake","ai-voice","family-emergency","mom","dad","son","daughter","grandson","granddaughter","nephew","niece","brother","sister","parent","child","relative","bail","hospital","accident","arrested","detained","stranded"]);
  const modernSocialDmWords = new Set(["dm","direct-message","message-me","inbox-me","whatsapp","telegram","signal","discord","instagram","facebook","tiktok","snapchat","x-com","twitter","influencer","creator","celebrity","mentor","coach","giveaway","collab","sponsorship","verification-badge","blue-check","promo","brand-deal"]);
  const modernMarketplaceWords = new Set(["marketplace","kijiji","craigslist","facebook-marketplace","buyer","seller","item","listing","purchase","pickup","courier","shipping-agent","mover","overpayment","extra-payment","refund-extra","buyer-protection","seller-protection","payment-pending","release-funds","escrow","deposit","e-transfer-pending","interac-pending"]);
  const modernStudentSchoolWords = new Set(["student","school","college","university","campus","scholarship","grant","bursary","tuition","tuition-refund","student-aid","financial-aid","exam","transcript","student-portal","learning-portal","internship","campus-job","school-login","education-refund"]);
  const modernFakeRecoveryWords = new Set(["recover-stolen-funds","funds-recovery","crypto-recovery","wallet-recovery","scam-recovery","asset-recovery","chargeback-assistance","report-scam","crime-report","case-number","case-id","recovery-agent","investigator","refund-investigation","fraud-department","verify-bank-to-recover","recovery-fee","unlock-recovered-funds"]);
  const modernActionWords = new Set(["send","pay","transfer","wire","e-transfer","etransfer","interac","buy","purchase","upload","verify","confirm","validate","claim","redeem","release","unlock","recover","report","open","click","message","dm","contact","submit","provide","enter","connect","approve"]);
  const modernSensitiveWords = new Set(["bank","banking","card","credit-card","debit-card","cvv","wallet","seed","seed-phrase","private-key","password","login","otp","code","pin","id","identity","passport","license","student-id","sin","ssn","address","phone","email","photo","receipt"]);



  function escapeHtml(value){
    return String(value).replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#039;"}[ch]));
  }

  function stripWrappingPunctuation(value){
    let text = String(value || "").trim();
    let previous = "";
    while (text && text !== previous) {
      previous = text;
      text = text.replace(/^[<({\["'`]+/, "").trim();
      text = text.replace(/[.,;:!?]+$/, "").trim();
      text = text.replace(/[>)}\]"'`]+$/, "").trim();
      text = text.replace(/[.,;:!?]+$/, "").trim();
    }
    return text;
  }

  function extractBase64DecodedUrls(text){
    const decodedUrls = [];
    const tokens = String(text || "").match(/[A-Za-z0-9+/]{24,}={0,2}/g) || [];
    tokens.forEach(token => {
      try {
        let padded = token;
        while (padded.length % 4) padded += "=";
        const decoded = atob(padded);
        if (/https?:\/\//i.test(decoded) || /hxxps?:\/\//i.test(decoded)) {
          const matches = decoded.match(/https?:\/\/[^\s<>()"']+|hxxps?:\/\/[^\s<>()"']+/ig) || [];
          matches.forEach(url => decodedUrls.push(stripWrappingPunctuation(url)));
        }
      } catch(error) {}
    });
    return decodedUrls;
  }

  function extractCandidateUrls(value){
    const text = String(value || "");
    const sources = [text];
    let decoded = text;
    for (let i=0; i<2; i++) {
      if (!/%[0-9a-f]{2}/i.test(decoded)) break;
      const next = safeDecodeForInspection(decoded);
      if (!next || next === decoded) break;
      sources.push(next);
      decoded = next;
    }

    const found = [];
    sources.forEach(sourceText => {
      sourceText.replace(/\[[^\]]{1,80}\]\((https?:\/\/[^\s)]+)\)/ig, (_, url) => { found.push(stripWrappingPunctuation(url)); return _; });
      sourceText.replace(/<a\b[^>]*href=["'](https?:\/\/[^"']+)["'][^>]*>[\s\S]{0,300}?<\/a>/ig, (_, url) => { found.push(stripWrappingPunctuation(url)); return _; });
      sourceText.replace(/<form\b[^>]*action=["'](https?:\/\/[^"']+)["'][^>]*>/ig, (_, url) => { found.push(stripWrappingPunctuation(url)); return _; });
      sourceText.replace(/<meta\b[^>]*http-equiv=["']?refresh["']?[^>]*content=["'][^"']*url\s*=\s*(https?:\/\/[^"';> ]+)/ig, (_, url) => { found.push(stripWrappingPunctuation(url)); return _; });
      sourceText.replace(/(?:window\.location|location\.href|document\.location)\s*=\s*["'](https?:\/\/[^"']+)["']/ig, (_, url) => { found.push(stripWrappingPunctuation(url)); return _; });
      const rawMatches = sourceText.match(/https?:\/\/[^\s<>()"']+|hxxps?:\/\/[^\s<>()"']+|www\.[^\s<>()"']+|[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?:\/[^\s<>()"']*)?/ig) || [];
      rawMatches.forEach(item => found.push(stripWrappingPunctuation(item)));
    });

    const decodedBase64Matches = extractBase64DecodedUrls(text);
    decodedBase64Matches.forEach(item => found.push(stripWrappingPunctuation(item)));
    return Array.from(new Set(found.filter(Boolean)));
  }

  function inspectHtmlEmailArtifacts(raw){
    const text = String(raw || "");
    const lowered = text.toLowerCase();
    const findings = {
      isHtml: /<\s*(a|form|meta|script|button|img|table|div|span|html|body)\b/i.test(text),
      anchors: [], forms: [], metaRefresh: [], scriptRedirects: [], hidden: [], buttonLike: false, imageLinks: false
    };
    text.replace(/<a\b([^>]*)href=["']([^"']+)["']([^>]*)>([\s\S]{0,400}?)<\/a>/ig, (_, pre, href, post, label) => {
      const visible = String(label || "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
      findings.anchors.push({href: stripWrappingPunctuation(href), label: visible});
      if (/<img\b/i.test(label)) findings.imageLinks = true;
      if (/button|btn|cta|call-to-action/i.test(pre + " " + post + " " + label)) findings.buttonLike = true;
      return _;
    });
    text.replace(/<form\b[^>]*action=["']([^"']+)["'][^>]*>/ig, (_, action) => { findings.forms.push(stripWrappingPunctuation(action)); return _; });
    text.replace(/<meta\b[^>]*http-equiv=["']?refresh["']?[^>]*content=["']([^"']+)["'][^>]*>/ig, (_, content) => { findings.metaRefresh.push(String(content || "")); return _; });
    text.replace(/(?:window\.location|location\.href|document\.location|location\.replace)\s*(?:=|\()\s*["'](https?:\/\/[^"']+)["']/ig, (_, url) => { findings.scriptRedirects.push(stripWrappingPunctuation(url)); return _; });
    if (/display\s*:\s*none/i.test(lowered)) findings.hidden.push("display:none");
    if (/opacity\s*:\s*0(?:[;\s"]|$)/i.test(lowered)) findings.hidden.push("opacity:0");
    if (/font-size\s*:\s*0/i.test(lowered)) findings.hidden.push("font-size:0");
    if (/visibility\s*:\s*hidden/i.test(lowered)) findings.hidden.push("visibility:hidden");
    return findings;
  }

  function normalizeCandidateUrl(candidate){
    let value = stripWrappingPunctuation(String(candidate || "").trim());
    if (/^hxxps?:\/\//i.test(value)) value = value.replace(/^hxxp/i, "http");
    if (/^\/\//.test(value)) value = "https:" + value;
    if (/^www\./i.test(value) || looksLikeBareDomain(value)) value = "https://" + value.replace(/^www\./i, "www.");
    try {
      const url = new URL(value);
      const host = url.hostname.replace(/\.$/, "").toLowerCase();
      return {raw:candidate, href:url.href, host, root:getRootDomain(host), path:(url.pathname || "/") + (url.search || ""), scheme:url.protocol.replace(":", "")};
    } catch(error) {
      return null;
    }
  }

  function detectMessagePressure(text){
    const raw = normalizeUnicodeConfusables(text);
    const phrases = [
      "urgent", "act now", "verify now", "final notice", "last chance", "limited time", "account locked", "account suspended",
      "unusual activity", "suspicious activity", "security alert", "payment failed", "delivery fee", "customs fee", "redelivery fee",
      "refund available", "benefit payment", "tax refund", "deposit pending", "e-transfer", "interac", "click here", "open this link",
      "confirm your", "verify your", "update your", "enter your password", "one time code", "otp", "2fa", "mfa"
    ];
    return phrases.filter(item => raw.includes(item));
  }

  function classifyMessageEnvelope(raw, candidates){
    const text = String(raw || "");
    const lowered = normalizeUnicodeConfusables(text);
    if (/^\s*(sms|smsto|mailto|matmsg|mecard|begin:vcard|wifi:|otpauth:)/i.test(text)) return "Structured message/QR payload";
    if (/<form\b[^>]*action=/i.test(text) || /<meta\b[^>]*http-equiv=["']?refresh/i.test(text) || /(?:window\.location|location\.href|document\.location|location\.replace)\s*(?:=|\()/i.test(text)) return "HTML email/page snippet";
    if (/<a\b[^>]*href=/i.test(text)) return "HTML message/link snippet";
    if (/\[[^\]]{1,120}\]\(https?:\/\//i.test(text)) return "Markdown/chat link snippet";
    if ((candidates || []).length > 1) return "Multi-link message";
    if ((candidates || []).length === 1 && !(/^\s*(https?:\/\/|hxxps?:\/\/|www\.)/i.test(text) || looksLikeBareDomain(text.trim()))) return "Message with embedded link";
    if (/dear|hello|hi|account|payment|delivery|verify|click|refund|deposit|security|locked|urgent/i.test(lowered)) return "Message text";
    return "Direct target";
  }

  function analyzeMessageContext(raw, candidates, activeRoot){
    const text = String(raw || "");
    const normalizedText = normalizeUnicodeConfusables(text);
    const expandedCandidates = (candidates || []).concat(extractCandidateUrls(text));
    const unique = Array.from(new Set(expandedCandidates.filter(Boolean)));
    const roots = unique.map(normalizeCandidateUrl).filter(Boolean);
    const pressure = detectMessagePressure(normalizedText);
    const visibleBrandHints = findTrustedHintsInVisibleText(normalizedText);
    const active = String(activeRoot || "").toLowerCase();
    const mismatchedBrands = visibleBrandHints.filter(hit => {
      const family = brandFamilies.find(f => f.name === hit.family);
      if (!family || !active) return false;
      return !family.roots.some(root => active === root || active.endsWith("." + root));
    });
    const highRiskCandidates = roots.filter(item => {
      const root = item.root;
      const family = matchingTrustedFamily(root);
      const near = findNearMissInstitutionRoot(root).length > 0;
      const stuffed = findTrustedRootStuffedSubdomain(item.host, root).length > 0;
      const embedded = findEmbeddedTrustedDomainInPath(item.host, item.path, root).length > 0;
      const sensitive = Array.from(highValueWorkflowWords).some(word => (item.host + " " + item.path).toLowerCase().includes(word));
      const visibleFamilyInCandidate = visibleBrandHints.some(hit => {
        const fam = brandFamilies.find(f => f.name === hit.family);
        return fam && fam.aliases.some(alias => { const compactTarget = (item.host + " " + item.path).toLowerCase().replace(/[^a-z0-9]+/g, " "); const compactNoSpace = compactTarget.replace(/\s+/g, ""); const compactAlias = String(alias).toLowerCase().replace(/[^a-z0-9]+/g, ""); return alias.length >= 3 && (aliasMatches(compactTarget, alias) || compactNoSpace.includes(compactAlias)); });
      });
      return (!family && (near || stuffed || embedded || (sensitive && visibleFamilyInCandidate)));
    });
    return {
      envelope: classifyMessageEnvelope(text, unique),
      candidates: unique, roots, pressure, visibleBrandHints, mismatchedBrands, highRiskCandidates
    };
  }

  function looksLikeBareDomain(value){
    return /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(\/.*)?$/i.test(String(value || ""));
  }

  function preprocessRawInput(raw){
    const original = String(raw || "");
    let value = original.trim();
    const notes = [];
    if (value !== original) notes.push("Outer whitespace removed before analysis.");

    let markdownLabel = "";
    const markdownMatch = value.match(/^\[([^\]]{1,120})\]\((https?:\/\/[^\s)]+)\)$/i);
    if (markdownMatch) {
      markdownLabel = markdownMatch[1];
      value = markdownMatch[2];
      notes.push("Markdown link wrapper removed; Proxuma analyzed the destination inside parentheses.");
      if (markdownLabel) notes.push("Visible markdown label preserved for mismatch review: " + markdownLabel.slice(0,80));
    }

    const htmlAnchorMatch = value.match(/^<a\b[^>]*href=["'](https?:\/\/[^"']+)["'][^>]*>([\s\S]{1,160}?)<\/a>$/i);
    if (htmlAnchorMatch) {
      markdownLabel = htmlAnchorMatch[2].replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
      value = htmlAnchorMatch[1];
      notes.push("HTML anchor wrapper removed; Proxuma analyzed the href destination instead of the visible link text.");
      if (markdownLabel) notes.push("Visible HTML anchor label preserved for mismatch review: " + markdownLabel.slice(0,80));
    }

    const beforeWrap = value;
    value = stripWrappingPunctuation(value);
    if (value !== beforeWrap) notes.push("Common message punctuation/wrappers removed from the target boundary.");

    if (/^hxxps?:\/\//i.test(value)) {
      value = value.replace(/^hxxp/i, "http");
      notes.push("Obfuscated hxxp/hxxps scheme normalized so the destination can be judged.");
    }

    if (/^\/\/[^\s/]+/i.test(value)) {
      value = "https:" + value;
      notes.push("Protocol-relative link normalized with HTTPS so the real host can be judged.");
    }

    const lowerBoundary = value.toLowerCase();
    if (/^(javascript|data|file|vbscript|blob|chrome-extension|about|content):/i.test(value)) {
      notes.push("Dangerous local/script scheme preserved for direct scheme analysis.");
      return { original, value, notes, candidates: [], markdownLabel };
    }
    const candidates = extractCandidateUrls(value);
    if (qrStructuredPrefixes.some(prefix => lowerBoundary.startsWith(prefix))) {
      notes.push("Structured QR/message scheme preserved as payload; Proxuma did not extract a bare domain from inside it.");
      return { original, value, notes, candidates, markdownLabel };
    }
    const schemePrefix = (value.match(/^([a-z][a-z0-9+.-]*):/i) || ["",""])[1].toLowerCase();
    const knownNonHttpPayloadSchemes = new Set(["mailto","tel","sms","smsto","geo","matmsg","mecard","otpauth","wifi"]);
    if (schemePrefix && knownNonHttpPayloadSchemes.has(schemePrefix) && !/^https?:\/\//i.test(value)) {
      notes.push("Non-HTTP scheme preserved as payload; Proxuma did not extract a bare domain from inside it.");
      return { original, value, notes, candidates, markdownLabel };
    }

    const simpleUrlish = /^https?:\/\//i.test(value) || /^www\./i.test(value) || looksLikeBareDomain(value);
    const explicitPayloadContext = /\b(qr|payload|barcode|scan payload|qr payload|scanned code)\b/i.test(value);
    if (!simpleUrlish && explicitPayloadContext && candidates.length >= 1) {
      notes.push("Explicit QR/payload context preserved so embedded URLs can be deep-scanned inside payload mode.");
    } else if (!simpleUrlish && candidates.length === 1) {
      notes.push("One URL was extracted from surrounding message or QR text and scanned as the real destination.");
      value = candidates[0];
    } else if (!simpleUrlish && candidates.length > 1) {
      notes.push("Multiple URLs were found inside one payload; Proxuma kept it in payload mode instead of guessing one destination.");
    }
    return { original, value, notes, candidates, markdownLabel };
  }

  function normalizeTarget(raw){
    const prepared = preprocessRawInput(raw);
    const value = prepared.value;
    if (!value) return { type:"empty", raw:"", sourceRaw:prepared.original, normalizedRaw:value, normalizationNotes:prepared.notes, embeddedCandidates:prepared.candidates, markdownLabel:prepared.markdownLabel || "", display:"", host:"", root:"", href:"", path:"", scheme:"", username:"", port:"" };
    if (/^(javascript|data|file|vbscript|blob|chrome-extension|about|content):/i.test(value)) {
      const scheme = (value.match(/^([a-z0-9+.-]+):/i) || ["","unknown"])[1].toLowerCase();
      return { type:"dangerous-scheme", raw:value, sourceRaw:prepared.original, normalizedRaw:value, normalizationNotes:prepared.notes, embeddedCandidates:prepared.candidates, markdownLabel:prepared.markdownLabel || "", display:value, host:"Dangerous local/script scheme", root:"Dangerous local/script scheme", href:value, path:value, scheme, username:"", port:"" };
    }
    if (/^[a-z][a-z0-9+.-]*:/i.test(value) && !/^https?:\/\//i.test(value)) {
      const scheme = (value.match(/^([a-z0-9+.-]+):/i) || ["","unknown"])[1].toLowerCase();
      return { type:"payload", raw:value, sourceRaw:prepared.original, normalizedRaw:value, normalizationNotes:prepared.notes.concat(["Non-HTTP scheme kept in payload mode instead of extracting an inner domain."]), embeddedCandidates:prepared.candidates, markdownLabel:prepared.markdownLabel || "", display:value, host:"Non-URL payload", root:"Non-URL payload", href:value, path:"", scheme, username:"", port:"" };
    }
    const urlish = /^https?:\/\//i.test(value) || /^www\./i.test(value) || looksLikeBareDomain(value);
    if (!urlish) return { type:"payload", raw:value, sourceRaw:prepared.original, normalizedRaw:value, normalizationNotes:prepared.notes, embeddedCandidates:prepared.candidates, markdownLabel:prepared.markdownLabel || "", display:value, host:"Non-URL payload", root:"Non-URL payload", href:value, path:"", scheme:"payload", username:"", port:"" };
    try{
      const withScheme = /^https?:\/\//i.test(value) ? value : "https://" + value.replace(/^www\./i,"www.");
      const url = new URL(withScheme);
      const host = url.hostname.replace(/\.$/,"").toLowerCase();
      return { type:"url", raw:value, sourceRaw:prepared.original, normalizedRaw:value, normalizationNotes:prepared.notes, embeddedCandidates:prepared.candidates, markdownLabel:prepared.markdownLabel || "", display:url.href, host, root:getRootDomain(host), href:url.href, path:(url.pathname || "/") + (url.search || ""), scheme:url.protocol.replace(":",""), username:url.username || "", port:url.port || "" };
    }catch(error){
      const looksUrlLike = /^https?:\/\//i.test(value) || /^www\./i.test(value) || looksLikeBareDomain(value);
      return { type: looksUrlLike ? "payload" : "payload", raw:value, sourceRaw:prepared.original, normalizedRaw:value, normalizationNotes:prepared.notes, embeddedCandidates:prepared.candidates, markdownLabel:prepared.markdownLabel || "", display:value, host: looksUrlLike ? "Unreadable URL-like input" : "Non-URL payload", root: looksUrlLike ? "Unreadable URL-like input" : "Non-URL payload", href:value, path:value, scheme: looksUrlLike ? "unreadable" : "payload", username:"", port:"" };
    }
  }

  function getRootDomain(host){
    if (!host || host === "Non-URL payload") return host || "unknown";
    if (isIp(host)) return host;
    const parts = host.split(".").filter(Boolean);
    if (parts.length <= 2) return host;
    const last2 = parts.slice(-2).join(".");
    const last3 = parts.slice(-3).join(".");
    const commonSecondLevel = /\.(co|com|net|org|gov|ac)\.[a-z]{2}$/i;
    return commonSecondLevel.test(last3) ? last3 : last2;
  }

  function isIp(host){ return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || /^\[[0-9a-f:]+\]$/i.test(host) || /^[0-9a-f:]{3,}$/i.test(host) && host.includes(":"); }
  function tldOf(root){ const parts = String(root||"").split("."); return parts.length ? parts[parts.length-1] : ""; }
  function includesAny(text, list){ return list.filter(item => text.includes(item)); }
  function addSignal(arr, severity, title, detail, weight){ arr.push({severity, title, detail, weight}); }

  function tokenizeForMatch(text){
    return String(text || "").toLowerCase().match(/[a-z0-9@$]+/g) || [];
  }
  function aliasMatches(text, alias){
    const normalizedText = String(text || "").toLowerCase().replace(/[^a-z0-9]+/g, " ");
    const normalizedAlias = String(alias || "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
    if (!normalizedAlias) return false;
    if (normalizedAlias.length <= 3) {
      return new RegExp("(^|\\s)" + normalizedAlias.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "($|\\s)").test(normalizedText);
    }
    return normalizedText.includes(normalizedAlias) || normalizedText.replace(/\s+/g, "").includes(normalizedAlias.replace(/\s+/g, ""));
  }
  function normalizeLookalikeToken(token, oneAs){
    return String(token || "").toLowerCase()
      .replace(/0/g,"o")
      .replace(/1/g, oneAs || "i")
      .replace(/3/g,"e")
      .replace(/4/g,"a")
      .replace(/5/g,"s")
      .replace(/@/g,"a")
      .replace(/\$/g,"s");
  }

  function normalizeUnicodeConfusables(text){
    const map = {
      "а":"a","Α":"a","А":"a",
      "е":"e","Ε":"e","Е":"e",
      "і":"i","Ι":"i","І":"i","ı":"i",
      "о":"o","Ο":"o","О":"o",
      "р":"p","Ρ":"p","Р":"p",
      "с":"c","Ϲ":"c","С":"c",
      "х":"x","Χ":"x","Х":"x",
      "у":"y","Υ":"y","У":"y",
      "к":"k","Κ":"k","К":"k",
      "м":"m","Μ":"m","М":"m",
      "т":"t","Τ":"t","Т":"t",
      "в":"b","Β":"b","В":"b",
      "н":"h","Η":"h","Н":"h",
      "ј":"j","Ј":"j",
      "ѕ":"s","Ѕ":"s"
    };
    return String(text || "")
      .normalize("NFKC")
      .replace(/[аеіорсхуктмвнјѕΑАΕЕΙІΟОΡРϹСΧХΥУΚКΜМΤТΒВΗНЈЅı]/g, ch => map[ch] || ch)
      .toLowerCase();
  }
  function safeDecodeForInspection(text){
    try { return decodeURIComponent(String(text || "")); } catch(error) { return String(text || ""); }
  }

  function hasMalformedDomainPunctuation(target){
    const host = String((target && target.host) || "").toLowerCase();
    const raw = String((target && target.raw) || "").trim();
    const visibleAuthority = (raw.match(/^(?:https?:\/\/)?([^\/?#]+)/i) || ["",""])[1].toLowerCase();
    const illegalHostChars = /[,;"'<>\\|{}\[\]^`\s]/;
    if (illegalHostChars.test(host) || illegalHostChars.test(visibleAuthority)) return true;
    if (/\.{2,}/.test(host) || /(^|\.)-|-($|\.)/.test(host)) return true;
    return false;
  }

  function getVisibleAuthority(raw){
    return String(raw || "").trim().match(/^(?:[a-z][a-z0-9+.-]*:\/\/)?([^\/?#]+)/i)?.[1] || "";
  }

  function inspectDomainEndingSpoof(target){
    const raw = String((target && (target.sourceRaw || target.raw)) || "").trim();
    const host = String((target && target.host) || "").toLowerCase();
    const root = String((target && target.root) || "").toLowerCase();
    const authority = getVisibleAuthority(raw).toLowerCase();
    const candidate = authority || host || root || raw.toLowerCase();
    const normalizedCandidate = candidate.replace(/^www\./, "");
    const result = { active:false, severity:"medium", weight:0, title:"", detail:"", token:"", kind:"" };

    if (/(^|[a-z0-9-]),(com|net|org|ca|co|io|app|bank)(?:$|[\/?#:\s])/i.test(raw) || /[a-z0-9-]+,(com|net|org|ca|co|io|app|bank)$/i.test(normalizedCandidate)) {
      result.active = true;
      result.kind = "comma-domain";
      result.weight = 16;
      result.title = "Comma-domain punctuation trick";
      result.detail = "The visible destination uses a comma where a normal domain uses a dot, such as bank,com instead of bank.com. This can be used to make a copied or displayed address look familiar while breaking normal domain structure.";
      result.token = "comma-domain";
      return result;
    }

    const ending = (root.match(/\.([a-z0-9-]{2,12})$/i) || host.match(/\.([a-z0-9-]{2,12})$/i) || normalizedCandidate.match(/\.([a-z0-9-]{2,12})(?:$|[\/?:#\s])/i) || ["",""])[1].toLowerCase();
    const leetEnding = normalizeLookalikeToken(ending, "i");
    const suspiciousCom = ending && ending !== "com" && (leetEnding === "com" || /c0m|c0n|co[mn]0|c[o0][mn]/i.test(ending));
    if (suspiciousCom) {
      result.active = true;
      result.kind = "tld-lookalike";
      result.weight = 12;
      result.title = "Dot-com ending lookalike";
      result.detail = "The domain ending appears to imitate .com using lookalike characters, such as .c0m or .c0n. Treat this as suspicious because the ending is not the normal .com boundary users expect.";
      result.token = "." + ending + "→.com imitation";
      return result;
    }

    if (ending && /\d/.test(ending) && /[a-z]/.test(ending)) {
      result.active = true;
      result.kind = "mixed-tld";
      result.weight = 8;
      result.title = "Unusual mixed-letter domain ending";
      result.detail = "The domain ending mixes letters and numbers. Some legitimate systems may use unusual endings, but mixed endings can also imitate familiar TLDs.";
      result.token = "." + ending + " mixed ending";
      return result;
    }

    return result;
  }



  function inspectUrlIntelligenceExpansion(target){
    const raw = String((target && (target.href || target.raw)) || "");
    const host = String((target && target.host) || "").toLowerCase();
    const path = String((target && target.path) || "");
    const findings = {
      length: raw.length,
      hostLabels: host ? host.split(".").filter(Boolean).length : 0,
      pathDepth: path.split("/").filter(Boolean).length,
      percentCount: (raw.match(/%[0-9a-f]{2}/ig) || []).length,
      nestedEncoding: false,
      nestedUrlValue: false,
      numericHostLabel: false,
      longOpaqueValue: false,
      authBaitDensity: 0,
      structuralFlags: []
    };
    let parsed = null;
    try { parsed = new URL(target.href || target.raw); } catch(error) {}
    const decodedOnce = safeDecodeForInspection(raw);
    const decodedTwice = safeDecodeForInspection(decodedOnce);
    findings.nestedEncoding = /%25(?:2f|3a|40|5c|2e|3f|3d)/i.test(raw) || (decodedTwice !== decodedOnce && /https?:\/\//i.test(decodedTwice));
    findings.nestedUrlValue = /(?:https?%3a%2f%2f|https?:\/\/)/i.test(decodedOnce.replace(/&amp;/gi,"&"));
    const labels = host.split(".").filter(Boolean);
    findings.numericHostLabel = labels.some(function(label){
      if (!label || /^\d+$/.test(label) === false) return false;
      return label.length >= 5;
    });
    if (parsed) {
      const params = Array.from(parsed.searchParams.entries());
      findings.longOpaqueValue = params.some(function(pair){
        const value = String(pair[1] || "");
        if (value.length < 72) return false;
        const alphaNum = (value.match(/[a-z0-9]/ig) || []).length;
        const separators = (value.match(/[._~\-+/=]/g) || []).length;
        return alphaNum + separators >= Math.floor(value.length * 0.86);
      });
      const bait = /(login|signin|verify|verification|secure|account|password|passcode|otp|mfa|2fa|wallet|payment|invoice|refund|unlock|recover|reset)/ig;
      const joined = (parsed.pathname + " " + parsed.search).toLowerCase();
      findings.authBaitDensity = (joined.match(bait) || []).length;
    }
    if (findings.length >= 240) findings.structuralFlags.push("very-long-url");
    if (findings.hostLabels >= 6) findings.structuralFlags.push("deep-host-labels");
    if (findings.pathDepth >= 7) findings.structuralFlags.push("deep-path");
    if (findings.percentCount >= 8) findings.structuralFlags.push("heavy-percent-encoding");
    if (findings.nestedEncoding) findings.structuralFlags.push("nested-encoding");
    if (findings.nestedUrlValue) findings.structuralFlags.push("nested-destination");
    if (findings.numericHostLabel) findings.structuralFlags.push("numeric-host-label");
    if (findings.longOpaqueValue) findings.structuralFlags.push("opaque-query-value");
    if (findings.authBaitDensity >= 4) findings.structuralFlags.push("dense-auth-bait");
    return findings;
  }

  function inspectEncodedRiskTokens(target){
    const raw = String((target && (target.sourceRaw || target.raw || target.display || target.href)) || "");
    const path = String((target && target.path) || "");
    const display = String((target && target.display) || "");
    const combined = raw + " " + path + " " + display;
    const decodedOnce = safeDecodeForInspection(combined);
    const decodedTwice = safeDecodeForInspection(decodedOnce);
    const decodedLower = (decodedOnce + " " + decodedTwice).toLowerCase();
    const rawLower = combined.toLowerCase();
    const tokens = [];

    function add(token){
      if (token && !tokens.includes(token)) tokens.push(token);
    }

    if (/%[0-9a-f]{2}/i.test(combined)) add("percent-encoded content");
    if (/%2f/i.test(combined) || /%5c/i.test(combined) || decodedLower.includes("/")) {
      if (/%2f|%5c/i.test(combined)) add("encoded slash / path boundary");
    }
    if (/%3a/i.test(combined)) add("encoded colon");
    if (/%3f/i.test(combined)) add("encoded query marker");
    if (/%3d/i.test(combined)) add("encoded equals / parameter");
    if (/%26/i.test(combined)) add("encoded ampersand / chained parameter");
    if (/%40/i.test(combined)) add("encoded @ authority marker");

    const sensitiveWords = ["login", "logon", "signin", "sign-in", "secure", "verify", "verification", "password", "passcode", "otp", "mfa", "2fa", "account", "session", "token", "redirect", "return", "continue", "next", "url", "target", "auth", "authenticate"];
    sensitiveWords.forEach(word => {
      if (decodedLower.includes(word) && (!rawLower.includes(word) || /%[0-9a-f]{2}/i.test(combined))) {
        if (["login", "logon", "signin", "sign-in"].includes(word)) add("encoded login keyword");
        else if (["secure", "verify", "verification"].includes(word)) add("encoded verification/security word");
        else if (["password", "passcode", "otp", "mfa", "2fa"].includes(word)) add("encoded credential/MFA word");
        else if (["redirect", "return", "continue", "next", "url", "target"].includes(word)) add("encoded redirect/navigation word");
        else if (["session", "token", "auth", "authenticate"].includes(word)) add("encoded session/auth token word");
        else add("encoded " + word + " word");
      }
    });

    const compactDecoded = decodedLower.replace(/[^a-z0-9]+/g, " ");
    if (/login|signin|verify|password|otp|mfa|2fa/.test(compactDecoded) && /%[0-9a-f]{2}/i.test(combined)) add("obfuscated credential path");
    if (/https?:\/\//i.test(decodedOnce) && !/https?:\/\//i.test(raw)) add("encoded embedded URL");
    if (/%25[0-9a-f]{2}/i.test(combined)) add("double-encoded marker");

    return tokens.slice(0, 10);
  }

  function parsedUrlForTarget(target){
    try { return target && target.display ? new URL(target.display) : null; } catch(error) { return null; }
  }

  function inspectQueryParams(target){
    const url = parsedUrlForTarget(target);
    const findings = { redirect: [], credential: [], longValueCount: 0, count: 0 };
    if (!url) return findings;
    url.searchParams.forEach((value, key) => {
      const name = String(key || "").toLowerCase().replace(/[^a-z0-9_:-]/g, "");
      const rawValue = String(value || "");
      const decoded = safeDecodeForInspection(rawValue).toLowerCase();
      findings.count += 1;
      if (rawValue.length > 90) findings.longValueCount += 1;
      const compactName = name.replace(/[^a-z0-9]/g, "");
      const googleOutboundQ = target.root === "google.com" && String(url.pathname || "").toLowerCase() === "/url" && (name === "q" || compactName === "q");
      if (redirectParamNames.has(name) || redirectParamNames.has(compactName) || googleOutboundQ) {
        if (/https?:\/\//i.test(rawValue) || /https?:\/\//i.test(decoded) || /%2f%2f/i.test(rawValue) || /\/\//.test(decoded)) {
          findings.redirect.push(name || key);
        }
      }
      if (credentialParamNames.has(name) || credentialParamNames.has(compactName)) {
        findings.credential.push(name || key);
      }
    });
    return findings;
  }

  function findDoubleExtension(path){
    const lower = String(path || "").toLowerCase().split(/[?#]/)[0];
    return harmlessFileBaits.some(bait => lower.includes(bait + ".") || lower.includes(bait + "-")) && riskyExtensions.some(ext => lower.endsWith(ext) || lower.includes(ext + ".") || lower.includes(ext + "%"));
  }


  function pathHasExtension(text, extensions){
    const lower = safeDecodeForInspection(String(text || "")).toLowerCase();
    return extensions.filter(ext => {
      const escaped = ext.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      return new RegExp(escaped + "(?:$|[?#&;=%/._-])", "i").test(lower);
    });
  }

  function inspectDownloadTrap(target){
    const raw = String((target && (target.sourceRaw || target.raw || target.href)) || "");
    const path = String((target && target.path) || "");
    const decodedRaw = safeDecodeForInspection(raw);
    const decodedPath = safeDecodeForInspection(path);
    const full = (raw + " " + decodedRaw + " " + path + " " + decodedPath).toLowerCase();
    const findings = { executable: [], archive: [], doubleExtension: false, downloadWords: [], paramExecutable: [], paramArchive: [], paramDownloadWords: [] };
    findings.executable = Array.from(new Set(pathHasExtension(full, riskyExtensions)));
    findings.archive = Array.from(new Set(pathHasExtension(full, compressedDeliveryExtensions)));
    findings.doubleExtension = findDoubleExtension(full);
    findings.downloadWords = Array.from(downloadTrapWords).filter(word => full.includes(word));
    const url = parsedUrlForTarget(target);
    if (url) {
      url.searchParams.forEach((value, key) => {
        const name = String(key || "").toLowerCase().replace(/[^a-z0-9_-]/g, "");
        const compactName = name.replace(/[^a-z0-9]/g, "");
        const decodedValue = safeDecodeForInspection(value || "").toLowerCase();
        const inspect = name + " " + compactName + " " + decodedValue;
        if (executableParamNames.has(name) || executableParamNames.has(compactName)) findings.paramDownloadWords.push(name || key);
        const exts = pathHasExtension(inspect, riskyExtensions);
        const archives = pathHasExtension(inspect, compressedDeliveryExtensions);
        if (exts.length) findings.paramExecutable.push((name || key) + "=" + exts.join("/"));
        if (archives.length) findings.paramArchive.push((name || key) + "=" + archives.join("/"));
      });
    }
    findings.hasAny = findings.executable.length || findings.archive.length || findings.doubleExtension || findings.downloadWords.length || findings.paramExecutable.length || findings.paramArchive.length || findings.paramDownloadWords.length;
    return findings;
  }

  function findSensitiveWorkflowDensity(host, path){
    const text = String(host + " " + path + " " + safeDecodeForInspection(path)).toLowerCase();
    const hits = Array.from(sensitiveWorkflowWords).filter(word => text.includes(word));
    return Array.from(new Set(hits));
  }

  function inspectCredentialHarvestIntent(target, messageContext){
    const raw = String((target && (target.sourceRaw || target.raw || target.href)) || "");
    const path = String((target && target.path) || "");
    const host = String((target && target.host) || "");
    const decodedRaw = safeDecodeForInspection(raw);
    const decodedPath = safeDecodeForInspection(path);
    const text = (host + " " + path + " " + decodedPath + " " + raw + " " + decodedRaw).toLowerCase();
    const query = inspectQueryParams(target);
    const groups = {
      credential: Array.from(credentialIntentWords).filter(word => text.includes(word)),
      collection: Array.from(credentialCollectionWords).filter(word => text.includes(word)),
      financial: Array.from(credentialFinancialWords).filter(word => text.includes(word)),
      pressure: Array.from(credentialPressureWords).filter(word => text.includes(word)),
      credentialParams: query.credential || []
    };
    const messagePressure = (messageContext && messageContext.pressure) || [];
    const messageBrandMismatch = (messageContext && messageContext.mismatchedBrands && messageContext.mismatchedBrands.length) || 0;
    const rootedTrusted = target && isKnownRoot(target);
    const credentialDensity = groups.credential.length + groups.collection.length + groups.financial.length + groups.pressure.length + groups.credentialParams.length + Math.min(3, messagePressure.length);
    const hasPasswordToken = /\b(password|passwd|pwd|otp|2fa|mfa|pin|token|session|credential|credentials)\b/i.test(text) || groups.credentialParams.length >= 2;
    const hasLoginCollection = groups.credential.length >= 2 && (groups.collection.length >= 1 || groups.financial.length >= 1 || messagePressure.length >= 2);
    const hasImpersonationContext = messageBrandMismatch || findTrustedRootStuffedSubdomain(host, target.root).length || findEmbeddedTrustedDomainInPath(host, path, target.root).length || findNearMissInstitutionRoot(target.root).length;
    const active = hasPasswordToken || hasLoginCollection || (credentialDensity >= 5) || (hasImpersonationContext && groups.credential.length >= 1);
    return { active, rootedTrusted, credentialDensity, hasPasswordToken, hasLoginCollection, hasImpersonationContext, groups };
  }


  function extractPhoneLikeValues(text){
    const raw = String(text || "");
    const matches = raw.match(/(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}|\b\d{3}[\s.-]\d{4}\b|\b\d{10}\b)/g) || [];
    return Array.from(new Set(matches.map(item => item.replace(/\s+/g, " ").trim()))).slice(0, 5);
  }

  function inspectCallbackScamIntent(target, messageContext){
    const raw = String((target && (target.sourceRaw || target.raw || target.href)) || "");
    const path = String((target && target.path) || "");
    const host = String((target && target.host) || "");
    const decoded = safeDecodeForInspection(raw + " " + path);
    const text = (raw + " " + decoded + " " + host + " " + path).toLowerCase();
    const phones = extractPhoneLikeValues(raw + " " + decoded);
    const hasTelScheme = /^tel:/i.test(String((target && target.raw) || "")) || /\btel:/i.test(raw);
    const callWords = Array.from(callbackIntentWords).filter(word => text.includes(word));
    const pressure = Array.from(callbackPressureWords).filter(word => text.includes(word));
    const sensitive = Array.from(callbackSensitiveWords).filter(word => text.includes(word));
    const messagePressure = (messageContext && messageContext.pressure) || [];
    const visibleBrands = (messageContext && messageContext.visibleBrandHints) || [];
    const nonTrustedRoot = target && target.type === "url" ? !isKnownRoot(target) : true;
    const hasPhoneRoute = phones.length > 0 || hasTelScheme;
    const hasCallIntent = hasPhoneRoute && (callWords.length > 0 || /\b(call|phone|support|refund|fraud|security|billing|bank|delivery|tax)\b/i.test(text));
    const sensitivePressure = pressure.length + Math.min(3, messagePressure.length) + sensitive.length;
    const active = hasPhoneRoute && (sensitivePressure >= 2 || visibleBrands.length > 0 || (hasCallIntent && (sensitive.length > 0 || pressure.length > 0 || messagePressure.length > 0)));
    let severity = "low";
    let weight = 4;
    if (active && (sensitivePressure >= 3 || (visibleBrands.length && nonTrustedRoot) || /gift-?card|crypto|wallet|otp|pin|password|refund|banking|fraud/i.test(text))) { severity = "high"; weight = 22; }
    else if (active) { severity = "medium"; weight = 12; }
    return {active, severity, weight, phones, hasTelScheme, callWords, pressure, sensitive, visibleBrands, nonTrustedRoot};
  }



  function inspectDeliveryCustomsScamIntent(target, messageContext){
    const raw = String((target && (target.sourceRaw || target.raw || target.href)) || "");
    const path = String((target && target.path) || "");
    const host = String((target && target.host) || "");
    const decoded = safeDecodeForInspection(raw + " " + path);
    const normalized = (host + " " + path + " " + raw + " " + decoded).toLowerCase().replace(/[\s_]+/g,"-");
    const plain = (raw + " " + decoded + " " + host + " " + path).toLowerCase();
    const visibleBrands = (messageContext && messageContext.visibleBrandHints) || [];
    const mismatchedBrands = (messageContext && messageContext.mismatchedBrands) || [];
    const msgPressure = (messageContext && messageContext.pressure) || [];
    const trusted = target && target.root && matchingTrustedFamily(target.root);
    const deliveryIntent = Array.from(deliveryIntentWords).filter(word => normalized.includes(word));
    const carriers = Array.from(deliveryCarrierWords).filter(word => normalized.includes(word));
    const actions = Array.from(deliveryActionWords).filter(word => normalized.includes(word));
    const pressure = Array.from(deliveryPressureWords).filter(word => normalized.includes(word));
    const sensitive = Array.from(deliverySensitiveWords).filter(word => normalized.includes(word));
    const feeWords = Array.from(deliveryFeeWords).filter(word => normalized.includes(word));
    const portalWords = Array.from(deliveryPortalWords).filter(word => normalized.includes(word));
    const trackingPattern = /\b(?:tracking|track|shipment|parcel|package|delivery)[-\s_]*(?:id|number|no|#|code)?\b/i.test(plain) || /\b[A-Z]{1,3}\d{6,}[A-Z0-9]*\b/.test(raw);
    const customsPattern = /(?:customs|duty|duties|import\s?fee|clearance|border\s?fee|tax\s?fee|release\s?fee)/i.test(raw);
    const redeliveryPattern = /(?:redelivery|re[-\s]?delivery|reschedule|missed\s?delivery|delivery\s?failed|failed\s?delivery|undelivered|return\s?to\s?sender|held\s?(?:package|parcel|shipment)|package\s?held)/i.test(raw);
    const addressPattern = /(?:confirm|update|verify|correct|provide|submit).{0,40}(?:address|delivery\s?address|shipping\s?address)/i.test(raw);
    const parcelFeePattern = /(?:pay|settle|clear|release|unlock).{0,55}(?:delivery|shipping|redelivery|customs|duty|clearance|storage|postage|handling).{0,35}(?:fee|charge|tax|amount|payment)|(?:delivery|shipping|redelivery|customs|duty|clearance|storage|postage|handling).{0,35}(?:fee|charge|tax|amount|payment).{0,55}(?:pay|settle|clear|release|unlock)/i.test(raw);
    const missedSignaturePattern = /(?:missed|attempted|failed).{0,35}(?:signature|recipient|delivery\s?attempt)|(?:signature|required|recipient).{0,35}(?:reschedule|redelivery|confirm|verify)/i.test(raw);
    const trackingPortalPattern = /(?:tracking|parcel|package|shipment|delivery).{0,35}(?:portal|center|centre|secure|confirmation|correction)|(?:portal|center|centre).{0,35}(?:tracking|parcel|package|shipment|delivery)/i.test(raw);
    const density = deliveryIntent.length + carriers.length + actions.length + pressure.length + sensitive.length + feeWords.length + portalWords.length + Math.min(3, msgPressure.length) + (trackingPattern?1:0) + (customsPattern?2:0) + (redeliveryPattern?2:0) + (addressPattern?2:0) + (parcelFeePattern?3:0) + (missedSignaturePattern?2:0) + (trackingPortalPattern?2:0) + mismatchedBrands.length;
    const hasDeliveryContext = deliveryIntent.length || carriers.length || trackingPattern || customsPattern || redeliveryPattern || addressPattern || parcelFeePattern || missedSignaturePattern || trackingPortalPattern || feeWords.length || portalWords.length || (mismatchedBrands.length && (deliveryIntent.length || carriers.length));
    const active = !trusted && hasDeliveryContext && (
      (deliveryIntent.length >= 2 && (actions.length || pressure.length || sensitive.length || feeWords.length || portalWords.length || msgPressure.length || carriers.length)) ||
      (carriers.length && (trackingPattern || redeliveryPattern || customsPattern || addressPattern || parcelFeePattern || missedSignaturePattern || trackingPortalPattern) && (actions.length || pressure.length || sensitive.length || feeWords.length)) ||
      ((customsPattern || redeliveryPattern || addressPattern || parcelFeePattern || missedSignaturePattern || trackingPortalPattern) && deliveryIntent.length && (actions.length || pressure.length || sensitive.length || feeWords.length || msgPressure.length)) ||
      (mismatchedBrands.length && (deliveryIntent.length || carriers.length)) ||
      (density >= 6 && (deliveryIntent.length || carriers.length || customsPattern || redeliveryPattern || parcelFeePattern || trackingPortalPattern))
    );
    const high = customsPattern || redeliveryPattern || addressPattern || parcelFeePattern || missedSignaturePattern || trackingPortalPattern || carriers.length >= 1 || pressure.length >= 2 || sensitive.length >= 2 || feeWords.length || mismatchedBrands.length || density >= 8;
    const severity = high ? "high" : "medium";
    const weight = high ? 23 : 12;
    return {active, severity, weight, deliveryIntent, carriers, actions, pressure, sensitive, feeWords, portalWords, trackingPattern, customsPattern, redeliveryPattern, addressPattern, parcelFeePattern, missedSignaturePattern, trackingPortalPattern, visibleBrands, mismatchedBrands, trusted, density, hasDeliveryContext};
  }

  function inspectParkingTollTransitScamIntent(target, messageContext){
    const raw = String((target && (target.sourceRaw || target.raw || target.href)) || "");
    const path = String((target && target.path) || "");
    const host = String((target && target.host) || "");
    const decoded = safeDecodeForInspection(raw + " " + path);
    const normalized = (host + " " + path + " " + raw + " " + decoded).toLowerCase().replace(/[^a-z0-9.]+/g,"-");
    const readable = (host + " " + path + " " + raw + " " + decoded).toLowerCase();
    const visibleBrands = (messageContext && messageContext.visibleBrandHints) || [];
    const mismatchedBrands = (messageContext && messageContext.mismatchedBrands) || [];
    const msgPressure = (messageContext && messageContext.pressure) || [];
    const trusted = target && target.root && matchingTrustedFamily(target.root);
    const intent = Array.from(parkingTollTransitIntentWords).filter(word => normalized.includes(word));
    const actions = Array.from(parkingTollTransitActionWords).filter(word => normalized.includes(word));
    const pressure = Array.from(parkingTollTransitPressureWords).filter(word => normalized.includes(word));
    const sensitive = Array.from(parkingTollTransitSensitiveWords).filter(word => normalized.includes(word));
    const platePattern = /(?:license|licence)[-\s]?plate|plate[-\s]?(?:number|lookup|verify)|vehicle[-\s]?(?:plate|registration)|vin/i.test(readable);
    const tollPattern = /(?:toll|turnpike|407[-\s]?etr|e[-\s]?zpass|ezpass|fastrak|sunpass|unpaid[-\s]?toll)/i.test(readable);
    const parkingQrPattern = /(?:parking[-\s]?meter|pay[-\s]?parking|parking[-\s]?(?:fee|session|violation|ticket)|scan[-\s]?(?:to|for)[-\s]?pay)/i.test(readable);
    const ticketPattern = /(?:citation|violation|ticket|fine|penalty|infraction|tow|impound|enforcement)/i.test(readable);
    const transitPattern = /(?:transit|fare|fare[-\s]?card|presto|metrocard|bus|train|subway|station[-\s]?ticket)/i.test(readable);
    const density = intent.length + actions.length + pressure.length + sensitive.length + Math.min(3, msgPressure.length) + (platePattern?2:0) + (tollPattern?2:0) + (parkingQrPattern?2:0) + (ticketPattern?2:0) + (transitPattern?1:0) + mismatchedBrands.length;
    const mobilityAnchor = intent.length || parkingQrPattern || tollPattern || ticketPattern || platePattern || transitPattern;
    const active = !trusted && mobilityAnchor && (
      ((parkingQrPattern || tollPattern || ticketPattern || platePattern || transitPattern) && (actions.length || pressure.length || sensitive.length || msgPressure.length)) ||
      (intent.length >= 2 && (actions.length || pressure.length || sensitive.length || msgPressure.length)) ||
      (mismatchedBrands.length && (intent.length || ticketPattern || tollPattern)) ||
      density >= 6
    );
    const high = tollPattern || ticketPattern || platePattern || pressure.length >= 2 || sensitive.length >= 2 || mismatchedBrands.length || density >= 8;
    const severity = high ? "high" : "medium";
    const weight = high ? 21 : 11;
    return {active, severity, weight, intent, actions, pressure, sensitive, platePattern, tollPattern, parkingQrPattern, ticketPattern, transitPattern, mobilityAnchor, visibleBrands, mismatchedBrands, trusted, density};
  }

  function inspectGovernmentTaxLegalThreatIntent(target, messageContext){
    const raw = String((target && (target.sourceRaw || target.raw || target.href)) || "");
    const path = String((target && target.path) || "");
    const host = String((target && target.host) || "");
    const decoded = safeDecodeForInspection(raw + " " + path);
    const normalized = (host + " " + path + " " + raw + " " + decoded).toLowerCase().replace(/[\s_]+/g,"-");
    const plain = (raw + " " + decoded + " " + host + " " + path).toLowerCase();
    const visibleBrands = (messageContext && messageContext.visibleBrandHints) || [];
    const mismatchedBrands = (messageContext && messageContext.mismatchedBrands) || [];
    const msgPressure = (messageContext && messageContext.pressure) || [];
    const trusted = target && target.root && matchingTrustedFamily(target.root);
    const intent = Array.from(governmentTaxLegalIntentWords).filter(word => normalized.includes(word));
    const actions = Array.from(governmentActionWords).filter(word => normalized.includes(word));
    const pressure = Array.from(governmentPressureWords).filter(word => normalized.includes(word));
    const sensitive = Array.from(governmentSensitiveWords).filter(word => normalized.includes(word));
    const taxRefundPattern = /(?:tax\s?refund|refund\s?(?:available|pending|approved)|cra|irs|hmrc|revenue\s?agency|tax\s?assessment|notice\s?of\s?assessment|tax\s?return|gst\/?hst|climate\s?(?:rebate|payment)|refund\s?portal)/i.test(plain);
    const benefitPattern = /(?:benefit|benefits|rebate|relief\s?payment|government\s?payment|deposit\s?pending|service\s?canada|social\s?security|medicare|medicaid|ei\s?benefit|cpp|oas|unclaimed\s?(?:benefit|payment|deposit)|benefit\s?(?:approved|pending|available))/i.test(plain);
    const legalThreatPattern = /(?:court|legal\s?notice|lawsuit|warrant|arrest|summons|citation|ticket|fine|penalty|violation|enforcement|failure\s?to\s?respond|case\s?(?:number|file)|collections|garnishment|hearing\s?notice|court\s?date)/i.test(plain);
    const idCollectionPattern = /(?:sin|ssn|tax\s?id|passport|driver'?s?\s?licen[cs]e|date\s?of\s?birth|dob|identity|verify\s?identity|photo\s?id|document\s?number|direct\s?deposit|bank\s?(?:account|details))/i.test(plain);
    const immigrationLicensePattern = /(?:immigration|visa|passport|work\s?permit|student\s?permit|citizenship|permanent\s?resident|pr\s?card|driver'?s?\s?licen[cs]e|licen[cs]e\s?(?:renewal|suspended|update)|dmv|mto)/i.test(plain);
    const agencyPortalPattern = /(?:secure\s?(?:government|agency|tax|benefit)\s?portal|official\s?(?:tax|benefit|government)\s?portal|my\s?cra|mycra|irs\s?portal|service\s?canada\s?account|verify\s?(?:your\s?)?(?:tax|benefit|government|identity)\s?(?:account|profile|record))/i.test(plain);
    const overpaymentPattern = /(?:overpayment|underpayment|arrears|balance\s?owing|amount\s?owing|repay(?:ment)?\s?(?:required|notice)|reassessment)/i.test(plain);
    const density = intent.length + actions.length + pressure.length + sensitive.length + Math.min(3, msgPressure.length) + (taxRefundPattern?2:0) + (benefitPattern?2:0) + (legalThreatPattern?3:0) + (idCollectionPattern?2:0) + (immigrationLicensePattern?2:0) + (agencyPortalPattern?2:0) + (overpaymentPattern?2:0) + mismatchedBrands.length;
    const governmentAnchor = intent.length || taxRefundPattern || benefitPattern || legalThreatPattern || idCollectionPattern || immigrationLicensePattern || agencyPortalPattern || overpaymentPattern || mismatchedBrands.length;
    const active = !trusted && governmentAnchor && (
      (intent.length >= 2 && (actions.length || pressure.length || sensitive.length || msgPressure.length || taxRefundPattern || legalThreatPattern || benefitPattern)) ||
      ((taxRefundPattern || benefitPattern || agencyPortalPattern || overpaymentPattern) && (actions.length || sensitive.length || pressure.length || msgPressure.length)) ||
      (legalThreatPattern && (actions.length || pressure.length || sensitive.length || msgPressure.length)) ||
      ((idCollectionPattern || immigrationLicensePattern) && intent.length && (actions.length || pressure.length || msgPressure.length || sensitive.length)) ||
      (mismatchedBrands.length && intent.length) ||
      density >= 7
    );
    const high = legalThreatPattern || taxRefundPattern || idCollectionPattern || agencyPortalPattern || overpaymentPattern || immigrationLicensePattern || sensitive.length >= 2 || pressure.length >= 2 || mismatchedBrands.length || density >= 9;
    const severity = high ? "high" : "medium";
    const weight = high ? 24 : 12;
    return {active, severity, weight, intent, actions, pressure, sensitive, taxRefundPattern, benefitPattern, legalThreatPattern, idCollectionPattern, immigrationLicensePattern, agencyPortalPattern, overpaymentPattern, governmentAnchor, visibleBrands, mismatchedBrands, trusted, density};
  }

  function inspectFakeSecurityTechSupportIntent(target, messageContext){
    const raw = String((target && (target.sourceRaw || target.raw || target.href)) || "");
    const path = String((target && target.path) || "");
    const host = String((target && target.host) || "");
    const decoded = safeDecodeForInspection(raw + " " + path);
    const normalized = (host + " " + path + " " + raw + " " + decoded).toLowerCase().replace(/[\s_]+/g,"-");
    const plain = (raw + " " + decoded + " " + host + " " + path).toLowerCase();
    const visibleBrands = (messageContext && messageContext.visibleBrandHints) || [];
    const mismatchedBrands = (messageContext && messageContext.mismatchedBrands) || [];
    const msgPressure = (messageContext && messageContext.pressure) || [];
    const trusted = target && target.root && matchingTrustedFamily(target.root);
    const intent = Array.from(fakeSecurityAlertIntentWords).filter(word => normalized.includes(word));
    const actions = Array.from(fakeSecurityActionWords).filter(word => normalized.includes(word));
    const pressure = Array.from(fakeSecurityPressureWords).filter(word => normalized.includes(word));
    const sensitive = Array.from(fakeSecuritySensitiveWords).filter(word => normalized.includes(word));
    const popupPattern = /(?:virus|malware|spyware|trojan|threat|device|computer|browser).{0,45}(?:infected|compromised|at\s?risk|blocked|locked|detected)/i.test(raw) || /(?:security|antivirus|defender|firewall).{0,45}(?:alert|warning|critical|detected|blocked)/i.test(raw);
    const supportCallPattern = /(?:call|contact|phone|dial).{0,45}(?:support|technician|agent|security|microsoft|apple|helpdesk|toll[-\s]?free)/i.test(raw) || extractPhoneLikeValues(raw + " " + decoded).length > 0 && /(?:support|security|virus|locked|infected|refund|account)/i.test(raw);
    const remoteAccessPattern = /(?:anydesk|teamviewer|ultraviewer|remote\s?access|screen\s?share|screenshare|grant\s?access|connect\s?to\s?(?:agent|technician)|support\s?session)/i.test(raw);
    const accountLockPattern = /(?:account|device|browser|computer|icloud|microsoft|apple|google).{0,45}(?:locked|blocked|suspended|compromised|unauthorized|unusual|suspicious)/i.test(raw);
    const captchaGatePattern = /(?:captcha|cloudflare|human\s?verification|verify\s?(?:you\s?are\s?)?human|security\s?check|browser\s?check).{0,80}(?:login|sign\s?in|account|password|verify|continue|document)|(?:login|sign\s?in|account|password|document).{0,80}(?:captcha|cloudflare|human\s?verification|security\s?check|browser\s?check)/i.test(plain);
    const density = intent.length + actions.length + pressure.length + sensitive.length + Math.min(3, msgPressure.length) + (popupPattern?3:0) + (supportCallPattern?3:0) + (remoteAccessPattern?3:0) + (accountLockPattern?2:0) + (captchaGatePattern?3:0) + mismatchedBrands.length;
    const active = !trusted && (
      (intent.length >= 2 && (actions.length || pressure.length || sensitive.length || msgPressure.length || popupPattern || supportCallPattern || remoteAccessPattern || accountLockPattern)) ||
      ((popupPattern || supportCallPattern || remoteAccessPattern || accountLockPattern || captchaGatePattern) && (actions.length || pressure.length || sensitive.length || msgPressure.length || intent.length)) ||
      (mismatchedBrands.length && intent.length) ||
      density >= 7
    );
    const high = popupPattern || supportCallPattern || remoteAccessPattern || accountLockPattern || captchaGatePattern || sensitive.length >= 2 || pressure.length >= 2 || mismatchedBrands.length || density >= 9;
    const severity = high ? "high" : "medium";
    const weight = high ? 24 : 12;
    return {active, severity, weight, intent, actions, pressure, sensitive, popupPattern, supportCallPattern, remoteAccessPattern, accountLockPattern, captchaGatePattern, visibleBrands, mismatchedBrands, trusted, density};
  }


  function inspectJobEmploymentScamIntent(target, messageContext){
    const raw = String((target && (target.sourceRaw || target.raw || target.href)) || "");
    const path = String((target && target.path) || "");
    const host = String((target && target.host) || "");
    const decoded = safeDecodeForInspection(raw + " " + path);
    const normalized = (host + " " + path + " " + raw + " " + decoded).toLowerCase().replace(/[\s_]+/g,"-");
    const plain = (raw + " " + decoded + " " + host + " " + path).toLowerCase();
    const visibleBrands = (messageContext && messageContext.visibleBrandHints) || [];
    const mismatchedBrands = (messageContext && messageContext.mismatchedBrands) || [];
    const msgPressure = (messageContext && messageContext.pressure) || [];
    const trusted = target && target.root && matchingTrustedFamily(target.root);
    const intent = Array.from(jobEmploymentIntentWords).filter(word => normalized.includes(word));
    const actions = Array.from(jobEmploymentActionWords).filter(word => normalized.includes(word));
    const pressure = Array.from(jobEmploymentPressureWords).filter(word => normalized.includes(word));
    const sensitive = Array.from(jobEmploymentSensitiveWords).filter(word => normalized.includes(word));
    const money = Array.from(jobEmploymentMoneyWords).filter(word => normalized.includes(word));
    const remoteWorkPattern = /(?:remote\s?work|work\s?from\s?home|wfh|online\s?job|part[-\s]?time\s?(?:remote|assistant)|virtual\s?assistant|data\s?entry|personal\s?assistant)/i.test(raw);
    const fakeOfferPattern = /(?:you\s?(?:have\s?)?been\s?(?:selected|shortlisted|approved)|job\s?offer|offer\s?letter|employment\s?offer|position\s?(?:approved|available)|guaranteed\s?(?:job|income|position)|pre[-\s]?approved\s?(?:candidate|role|position))/i.test(raw);
    const equipmentCheckPattern = /(?:equipment|laptop|software|starter\s?kit|training\s?kit|home\s?office).{0,70}(?:check|cheque|deposit|reimburse|purchase|vendor|supplier|fee|payment|wire|transfer)/i.test(raw) || /(?:check|cheque|deposit|reimburse|wire|transfer).{0,70}(?:equipment|laptop|software|starter\s?kit|vendor|supplier|home\s?office)/i.test(raw);
    const onboardingSensitivePattern = /(?:onboarding|payroll|direct\s?deposit|background\s?check|identity\s?verification|tax\s?form|w[-\s]?4|i[-\s]?9|td1|employee\s?portal).{0,85}(?:ssn|sin|bank|routing|account|passport|driver|license|licence|dob|date\s?of\s?birth|id|password|otp|pin|selfie|photo\s?id|void\s?(?:cheque|check))/i.test(raw);
    const chatOnlyPattern = /(?:telegram|whatsapp|signal|text\s?only|chat\s?interview|interview\s?by\s?(?:text|telegram|whatsapp)|message\s?(?:our|the)\s?(?:hiring\s?)?manager\s?on\s?(?:telegram|whatsapp|signal))/i.test(raw);
    const taskScamPattern = /(?:task\s?(?:job|platform|balance|commission)|complete\s?tasks|daily\s?tasks|recharge\s?(?:your\s?)?account|withdraw\s?(?:your\s?)?(?:commission|earnings)|unlock\s?(?:tasks|commission)|data\s?entry\s?tasks|product\s?review\s?tasks)/i.test(raw);
    const reshippingPattern = /(?:reship|re[-\s]?ship|package\s?forward|forward\s?packages|receive\s?and\s?(?:ship|forward)|shipping\s?assistant|warehouse\s?assistant|quality\s?control\s?inspector)/i.test(raw);
    const feeToStartPattern = /(?:application|processing|training|starter|activation|background\s?check|equipment).{0,45}(?:fee|payment|deposit)|(?:pay|send|transfer).{0,55}(?:fee|deposit).{0,55}(?:start|job|training|onboarding|equipment)/i.test(raw);
    const density = intent.length + actions.length + pressure.length + sensitive.length + money.length + Math.min(3, msgPressure.length) + (remoteWorkPattern?2:0) + (fakeOfferPattern?2:0) + (equipmentCheckPattern?4:0) + (onboardingSensitivePattern?4:0) + (chatOnlyPattern?3:0) + (taskScamPattern?4:0) + (reshippingPattern?4:0) + (feeToStartPattern?3:0) + mismatchedBrands.length;
    const employmentTheme = intent.length || remoteWorkPattern || fakeOfferPattern || equipmentCheckPattern || onboardingSensitivePattern || chatOnlyPattern || taskScamPattern || reshippingPattern || feeToStartPattern;
    const active = !trusted && (
      (intent.length >= 2 && (actions.length || pressure.length || sensitive.length || money.length || msgPressure.length || remoteWorkPattern || fakeOfferPattern)) ||
      ((equipmentCheckPattern || onboardingSensitivePattern || chatOnlyPattern || taskScamPattern || reshippingPattern || feeToStartPattern) && (intent.length || actions.length || pressure.length || sensitive.length || money.length || remoteWorkPattern)) ||
      (remoteWorkPattern && fakeOfferPattern && (actions.length || pressure.length || money.length || sensitive.length)) ||
      (mismatchedBrands.length && intent.length) ||
      (employmentTheme && density >= 7)
    );
    const high = equipmentCheckPattern || onboardingSensitivePattern || taskScamPattern || reshippingPattern || feeToStartPattern || sensitive.length >= 2 || money.length >= 2 || chatOnlyPattern || mismatchedBrands.length || density >= 9;
    const severity = high ? "high" : "medium";
    const weight = high ? 26 : 13;
    return {active, severity, weight, intent, actions, pressure, sensitive, money, remoteWorkPattern, fakeOfferPattern, equipmentCheckPattern, onboardingSensitivePattern, chatOnlyPattern, taskScamPattern, reshippingPattern, feeToStartPattern, visibleBrands, mismatchedBrands, trusted, density, employmentTheme};
  }

  function inspectModernScamCoveragePack(target, messageContext){
    const raw = String((target && (target.sourceRaw || target.raw || target.href)) || "");
    const path = String((target && target.path) || "");
    const host = String((target && target.host) || "");
    const decoded = safeDecodeForInspection(raw + " " + path);
    const normalized = (host + " " + path + " " + raw + " " + decoded).toLowerCase().replace(/[\s_]+/g,"-");
    const plain = (raw + " " + decoded + " " + host + " " + path).toLowerCase();
    const msgPressure = (messageContext && messageContext.pressure) || [];
    const mismatchedBrands = (messageContext && messageContext.mismatchedBrands) || [];
    const trusted = target && target.root && matchingTrustedFamily(target.root);
    const actions = Array.from(modernActionWords).filter(word => normalized.includes(word));
    const sensitive = Array.from(modernSensitiveWords).filter(word => normalized.includes(word));
    const add = (findings, key, severity, weight, sample, detail, density) => findings.push({key, active:true, severity, weight, sample, detail, density});
    const findings = [];

    const ai = Array.from(modernAiEmergencyWords).filter(word => normalized.includes(word));
    const aiEmergencyPattern = /(?:new\s?(?:number|phone)|lost\s?phone|broken\s?phone|don'?t\s?call|do\s?not\s?call|cannot\s?talk|can'?t\s?talk|text\s?only).{0,90}(?:send|transfer|wire|e[-\s]?transfer|interac|gift\s?card|crypto|money|bail|hospital|accident|arrest|detained|stranded)|(?:mom|dad|son|daughter|grandson|granddaughter|family|relative).{0,110}(?:emergency|accident|hospital|arrest|detained|bail|stranded).{0,110}(?:send|transfer|wire|money|gift\s?card|crypto|e[-\s]?transfer)/i.test(raw);
    const aiDensity = ai.length + actions.length + sensitive.length + Math.min(3,msgPressure.length) + (aiEmergencyPattern?5:0);
    if (!trusted && (aiEmergencyPattern || (ai.length >= 3 && (actions.length || sensitive.length || msgPressure.length)))) {
      add(findings, "AI / family emergency impersonation", "high", 27, aiEmergencyPattern ? "new-number/family-emergency money wording" : (ai[0] || "AI/emergency wording"), "The message resembles a modern family-emergency or AI/deepfake-style impersonation lure: urgent private contact, a new number or cannot-call excuse, and a request for money, gift cards, crypto, or verification.", aiDensity);
    }

    const dm = Array.from(modernSocialDmWords).filter(word => normalized.includes(word));
    const socialDmPattern = /(?:dm|message|inbox|contact).{0,45}(?:whatsapp|telegram|signal|discord|instagram|facebook|tiktok)|(?:giveaway|airdrop|mentor|investment|collab|sponsorship|verified|blue\s?check).{0,90}(?:dm|message|whatsapp|telegram|claim|verify|connect|pay|wallet)/i.test(raw);
    const dmDensity = dm.length + actions.length + sensitive.length + Math.min(3,msgPressure.length) + (socialDmPattern?3:0) + mismatchedBrands.length;
    if (!trusted && (socialDmPattern || (dm.length >= 2 && (actions.length || sensitive.length || msgPressure.length || mismatchedBrands.length)))) {
      add(findings, "Social media DM / influencer lure", dmDensity >= 8 || sensitive.length ? "high" : "medium", dmDensity >= 8 || sensitive.length ? 24 : 12, socialDmPattern ? "off-platform DM or giveaway/mentor wording" : (dm[0] || "social DM wording"), "The message pushes the user from a social platform into DMs, WhatsApp/Telegram/Signal, giveaways, mentorship, sponsorship, verification, or claim flows. Verify through the official profile/app before clicking, paying, or connecting accounts.", dmDensity);
    }

    const market = Array.from(modernMarketplaceWords).filter(word => normalized.includes(word));
    const marketplacePattern = /(?:buyer|seller|marketplace|kijiji|craigslist|listing|item).{0,100}(?:courier|shipping\s?agent|overpayment|extra\s?payment|refund\s?the\s?extra|payment\s?pending|release\s?funds|buyer\s?protection|escrow)|(?:courier|shipping\s?agent|overpayment|payment\s?pending|release\s?funds).{0,100}(?:item|listing|buyer|seller|pickup|marketplace)/i.test(raw);
    const marketAnchor = /(?:marketplace|kijiji|craigslist|facebook\s?marketplace|buyer|seller|listing|item|pickup|courier|shipping\s?agent|overpayment|buyer\s?protection|seller\s?protection|escrow)/i.test(raw);
    const marketDensity = market.length + actions.length + sensitive.length + Math.min(3,msgPressure.length) + (marketplacePattern?4:0) + (marketAnchor?2:0);
    if (!trusted && marketAnchor && (marketplacePattern || (market.length >= 2 && (actions.length || sensitive.length || msgPressure.length)))) {
      add(findings, "Marketplace buyer-seller scam", marketDensity >= 8 ? "high" : "medium", marketDensity >= 8 ? 24 : 12, marketplacePattern ? "courier/overpayment/payment-pending marketplace wording" : (market[0] || "marketplace wording"), "The message resembles a buyer-seller scam: courier pickup, overpayment, payment pending, escrow/buyer-protection links, or release-funds pressure. Keep payment and messaging inside the trusted marketplace where possible.", marketDensity);
    }

    const student = Array.from(modernStudentSchoolWords).filter(word => normalized.includes(word));
    const studentPattern = /(?:scholarship|student\s?grant|bursary|tuition\s?refund|student\s?aid|financial\s?aid|campus\s?job|internship).{0,90}(?:claim|verify|upload|bank|direct\s?deposit|student\s?id|login|password|pay|fee)|(?:school|college|university|campus|student\s?portal).{0,90}(?:verify|login|password|tuition|refund|grant|scholarship|exam|transcript)/i.test(raw);
    const studentDensity = student.length + actions.length + sensitive.length + Math.min(3,msgPressure.length) + (studentPattern?4:0);
    if (!trusted && (studentPattern || (student.length >= 2 && (actions.length || sensitive.length || msgPressure.length)))) {
      add(findings, "Student / school portal scam", studentDensity >= 8 || sensitive.length >= 2 ? "high" : "medium", studentDensity >= 8 || sensitive.length >= 2 ? 24 : 12, studentPattern ? "scholarship/tuition/student portal verification wording" : (student[0] || "student/school wording"), "The message resembles a student-targeted lure involving scholarships, grants, tuition refunds, campus jobs, portals, IDs, or school login verification. Verify through the official school site or student account typed manually.", studentDensity);
    }

    const recovery = Array.from(modernFakeRecoveryWords).filter(word => normalized.includes(word));
    const recoveryPattern = /(?:recover|recovery|retrieve|refund).{0,70}(?:stolen\s?funds|lost\s?crypto|wallet|asset|scam|chargeback|case|investigation).{0,90}(?:fee|bank|wallet|verify|deposit|unlock|release)|(?:report\s?(?:a\s?)?scam|crime\s?report|case\s?(?:id|number)).{0,90}(?:verify|bank|wallet|identity|refund|recover)/i.test(raw);
    const recoveryDensity = recovery.length + actions.length + sensitive.length + Math.min(3,msgPressure.length) + (recoveryPattern?5:0);
    if (!trusted && (recoveryPattern || (recovery.length >= 2 && (actions.length || sensitive.length || msgPressure.length)))) {
      add(findings, "Fake recovery / report portal scam", "high", 27, recoveryPattern ? "funds-recovery/report portal verification wording" : (recovery[0] || "fake recovery wording"), "The message resembles a second-stage recovery scam or fake report portal: recover stolen funds, crypto recovery, case-number pressure, refund investigation, or bank/wallet verification. Do not pay recovery fees or enter financial access details.", recoveryDensity);
    }

    return findings;
  }

  function inspectCryptoInvestmentScamIntent(target, messageContext){
    const raw = String((target && (target.sourceRaw || target.raw || target.href)) || "");
    const path = String((target && target.path) || "");
    const host = String((target && target.host) || "");
    const decoded = safeDecodeForInspection(raw + " " + path);
    const normalized = (host + " " + path + " " + raw + " " + decoded).toLowerCase().replace(/[\s_]+/g,"-");
    const visibleBrands = (messageContext && messageContext.visibleBrandHints) || [];
    const mismatchedBrands = (messageContext && messageContext.mismatchedBrands) || [];
    const msgPressure = (messageContext && messageContext.pressure) || [];
    const trusted = target && target.root && matchingTrustedFamily(target.root);
    const intent = Array.from(cryptoInvestmentIntentWords).filter(word => normalized.includes(word));
    const actions = Array.from(cryptoInvestmentActionWords).filter(word => normalized.includes(word));
    const pressure = Array.from(cryptoInvestmentPressureWords).filter(word => normalized.includes(word));
    const sensitive = Array.from(cryptoInvestmentSensitiveWords).filter(word => normalized.includes(word));
    const money = Array.from(cryptoInvestmentMoneyWords).filter(word => normalized.includes(word));
    const seedPhrasePattern = /(?:seed|recovery|secret|mnemonic).{0,35}(?:phrase|words|key)|(?:private\s?key|wallet\s?key|keystore)/i.test(raw);
    const guaranteedReturnPattern = /(?:guaranteed|risk[-\s]?free|no[-\s]?risk|double|triple|instant).{0,50}(?:profit|return|roi|yield|investment|money|crypto)|(?:profit|return|roi|yield).{0,50}(?:guaranteed|risk[-\s]?free|double|triple|instant)/i.test(raw);
    const walletConnectPattern = /(?:connect|sync|validate|verify|restore|recover|import|unlock).{0,45}(?:wallet|metamask|trust\s?wallet|ledger|trezor|seed|recovery|private\s?key)/i.test(raw);
    const recoveryFeePattern = /(?:recover|recovery|unlock|release|withdraw).{0,55}(?:funds|crypto|wallet|profit|account).{0,55}(?:fee|tax|gas|commission|deposit)|(?:fee|tax|gas|commission).{0,55}(?:recover|unlock|release|withdraw)/i.test(raw);
    const tradingBotPattern = /(?:trading\s?bot|copy\s?trading|forex\s?signals|crypto\s?signals|investment\s?group|pump\s?signal|high[-\s]?yield|staking\s?pool|liquidity\s?mining)/i.test(raw);
    const density = intent.length + actions.length + pressure.length + sensitive.length + money.length + Math.min(3, msgPressure.length) + (seedPhrasePattern?4:0) + (walletConnectPattern?3:0) + (guaranteedReturnPattern?3:0) + (recoveryFeePattern?3:0) + (tradingBotPattern?2:0) + mismatchedBrands.length;
    const cryptoTheme = intent.length || money.length || seedPhrasePattern || walletConnectPattern || recoveryFeePattern || guaranteedReturnPattern || tradingBotPattern;
    const active = !trusted && (
      (intent.length >= 2 && (actions.length || pressure.length || sensitive.length || money.length || msgPressure.length || guaranteedReturnPattern || tradingBotPattern)) ||
      ((seedPhrasePattern || walletConnectPattern || recoveryFeePattern) && (intent.length || actions.length || sensitive.length || money.length || pressure.length)) ||
      (guaranteedReturnPattern && (intent.length || money.length || actions.length)) ||
      (mismatchedBrands.length && intent.length) ||
      (cryptoTheme && density >= 7)
    );
    const high = seedPhrasePattern || walletConnectPattern || recoveryFeePattern || guaranteedReturnPattern || (cryptoTheme && sensitive.length >= 2) || money.length >= 3 || mismatchedBrands.length || (cryptoTheme && density >= 9);
    const severity = high ? "high" : "medium";
    const weight = high ? 26 : 13;
    return {active, severity, weight, intent, actions, pressure, sensitive, money, seedPhrasePattern, guaranteedReturnPattern, walletConnectPattern, recoveryFeePattern, tradingBotPattern, visibleBrands, mismatchedBrands, trusted, density};
  }



  function inspectRomanceTrustScamIntent(target, messageContext){
    const raw = String((target && (target.sourceRaw || target.raw || target.href)) || "");
    const path = String((target && target.path) || "");
    const host = String((target && target.host) || "");
    const decoded = safeDecodeForInspection(raw + " " + path);
    const normalized = (host + " " + path + " " + raw + " " + decoded).toLowerCase().replace(/[\s_]+/g,"-");
    const plain = (raw + " " + decoded + " " + host + " " + path).toLowerCase();
    const visibleBrands = (messageContext && messageContext.visibleBrandHints) || [];
    const mismatchedBrands = (messageContext && messageContext.mismatchedBrands) || [];
    const msgPressure = (messageContext && messageContext.pressure) || [];
    const trusted = target && target.root && matchingTrustedFamily(target.root);
    const intent = Array.from(romanceTrustIntentWords).filter(word => normalized.includes(word));
    const actions = Array.from(romanceTrustActionWords).filter(word => normalized.includes(word));
    const pressure = Array.from(romanceTrustPressureWords).filter(word => normalized.includes(word));
    const money = Array.from(romanceTrustMoneyWords).filter(word => normalized.includes(word));
    const sensitive = Array.from(romanceTrustSensitiveWords).filter(word => normalized.includes(word));
    const moveOffPlatformPattern = /(?:move|continue|message|chat|talk).{0,45}(?:telegram|whatsapp|signal|google\s?chat|hangouts|snapchat|text)|(?:telegram|whatsapp|signal|google\s?chat|hangouts).{0,45}(?:only|private|message|chat)/i.test(raw);
    const emergencyMoneyPattern = /(?:emergency|stuck|stranded|hospital|surgery|accident|detained|customs|visa|flight|ticket|hotel|rent|food).{0,70}(?:send|wire|transfer|pay|gift\s?card|crypto|bitcoin|money|funds|loan|fee)|(?:send|wire|transfer|pay|gift\s?card|crypto|bitcoin|money|funds).{0,70}(?:emergency|stuck|stranded|hospital|visa|flight|ticket|customs|rent)/i.test(raw);
    const loveTrustPattern = /(?:love|soulmate|relationship|future\s?together|trust\s?me|i\s?trust\s?you|secret|do\s?not\s?tell|don'?t\s?tell).{0,70}(?:money|funds|help|send|transfer|gift\s?card|crypto|ticket|visa|fee)/i.test(raw);
    const privateLeveragePattern = /(?:private|intimate|personal|photo|video|nude|secret).{0,60}(?:send|share|upload|expose|leak|blackmail)|(?:expose|leak|blackmail).{0,60}(?:photo|video|private|secret)/i.test(raw);
    const fakePersonaPattern = /(?:military|deployed|deployment|doctor|engineer|contractor|oil\s?rig|widow|widower|overseas|abroad).{0,80}(?:money|help|fee|ticket|visa|customs|hospital|emergency|gift\s?card|transfer)/i.test(raw);
    const density = intent.length + actions.length + pressure.length + money.length + sensitive.length + Math.min(3, msgPressure.length) + (moveOffPlatformPattern?2:0) + (emergencyMoneyPattern?4:0) + (loveTrustPattern?3:0) + (privateLeveragePattern?4:0) + (fakePersonaPattern?3:0) + mismatchedBrands.length;
    const active = !trusted && (
      ((emergencyMoneyPattern || loveTrustPattern || privateLeveragePattern || fakePersonaPattern) && (intent.length || actions.length || pressure.length || money.length || sensitive.length)) ||
      (moveOffPlatformPattern && (intent.length || pressure.length || money.length || sensitive.length)) ||
      (intent.length >= 2 && (actions.length || pressure.length || money.length || sensitive.length || msgPressure.length)) ||
      (mismatchedBrands.length && intent.length && (money.length || sensitive.length)) ||
      density >= 8
    );
    const high = emergencyMoneyPattern || privateLeveragePattern || fakePersonaPattern || money.length >= 2 || sensitive.length >= 2 || pressure.length >= 3 || density >= 10;
    const severity = high ? "high" : "medium";
    const weight = high ? 24 : 12;
    return {active, severity, weight, intent, actions, pressure, money, sensitive, moveOffPlatformPattern, emergencyMoneyPattern, loveTrustPattern, privateLeveragePattern, fakePersonaPattern, visibleBrands, mismatchedBrands, trusted, density};
  }




  function inspectAuthorityImpersonationVoice(target, messageContext){
    const raw = String((target && (target.sourceRaw || target.raw || target.href)) || "");
    const path = String((target && target.path) || "");
    const host = String((target && target.host) || "");
    const decoded = safeDecodeForInspection(raw + " " + path);
    const normalized = (raw + " " + decoded + " " + host + " " + path).toLowerCase().replace(/[\s_]+/g,"-");
    const readable = (raw + " " + decoded + " " + host + " " + path).toLowerCase();
    const trusted = target && target.root && matchingTrustedFamily(target.root);
    const msgPressure = (messageContext && messageContext.pressure) || [];
    const mismatchedBrands = (messageContext && messageContext.mismatchedBrands) || [];
    const visibleBrands = (messageContext && messageContext.visibleBrandHints) || [];
    const identities = Array.from(authorityVoiceIdentityWords).filter(word => normalized.includes(word));
    const claims = Array.from(authorityVoiceClaimWords).filter(word => normalized.includes(word));
    const actions = Array.from(authorityVoiceActionWords).filter(word => normalized.includes(word));
    const sensitive = Array.from(authorityVoiceSensitiveWords).filter(word => normalized.includes(word));
    const officialNoticePattern = /(?:official\s?(?:notice|communication|message)|department\s?(?:notice|review)|case\s?(?:id|number|file)|reference\s?(?:number|id)|ticket\s?(?:number|id))/i.test(readable);
    const departmentPersonaPattern = /(?:fraud|security|billing|compliance|legal|collections|payroll|hr|customs|tax|revenue|support).{0,40}(?:department|team|office|desk|agent|officer|representative)/i.test(readable);
    const authorityPlusActionPattern = /(?:official|department|case|reference|compliance|audit|investigation|review).{0,80}(?:verify|confirm|submit|provide|pay|call|download|open|sign|approve|authorize)/i.test(readable);
    const density = identities.length + claims.length + actions.length + sensitive.length + Math.min(3, msgPressure.length) + (officialNoticePattern?3:0) + (departmentPersonaPattern?3:0) + (authorityPlusActionPattern?2:0) + mismatchedBrands.length;
    const active = !trusted && (
      ((officialNoticePattern || departmentPersonaPattern || authorityPlusActionPattern) && (actions.length || sensitive.length || msgPressure.length || visibleBrands.length || mismatchedBrands.length)) ||
      (identities.length && claims.length && actions.length && (sensitive.length || msgPressure.length || visibleBrands.length)) ||
      (mismatchedBrands.length && (identities.length || claims.length)) ||
      density >= 8
    );
    const high = departmentPersonaPattern || authorityPlusActionPattern || mismatchedBrands.length || sensitive.length >= 2 || density >= 11;
    const severity = high ? "high" : "medium";
    const weight = high ? 18 : 9;
    return {active, severity, weight, identities, claims, actions, sensitive, officialNoticePattern, departmentPersonaPattern, authorityPlusActionPattern, visibleBrands, mismatchedBrands, trusted, density};
  }


  function inspectMfaOtpCodeTheft(target, messageContext){
    const raw = String((target && (target.sourceRaw || target.raw || target.href)) || "");
    const path = String((target && target.path) || "");
    const host = String((target && target.host) || "");
    const decoded = safeDecodeForInspection(raw + " " + path);
    const normalized = (raw + " " + decoded + " " + host + " " + path).toLowerCase().replace(/[\s_]+/g,"-");
    const readable = (raw + " " + decoded + " " + host + " " + path).toLowerCase();
    const trusted = target && target.root && matchingTrustedFamily(target.root);
    const msgPressure = (messageContext && messageContext.pressure) || [];
    const mismatchedBrands = (messageContext && messageContext.mismatchedBrands) || [];
    const visibleBrands = (messageContext && messageContext.visibleBrandHints) || [];
    const intent = Array.from(mfaOtpIntentWords).filter(word => normalized.includes(word));
    const actions = Array.from(mfaOtpActionWords).filter(word => normalized.includes(word));
    const context = Array.from(mfaOtpContextWords).filter(word => normalized.includes(word));
    const pressure = Array.from(mfaOtpPressureWords).filter(word => normalized.includes(word));
    const codeHarvestPattern = /(?:otp|one[\s-]?time\s?(?:code|password)|verification\s?code|security\s?code|login\s?code|sms\s?code|2fa|mfa|two[\s-]?factor).{0,80}(?:send|share|enter|provide|submit|reply|forward|copy|paste|verify|confirm)|(?:send|share|enter|provide|submit|reply|forward|copy|paste).{0,80}(?:otp|one[\s-]?time\s?(?:code|password)|verification\s?code|security\s?code|login\s?code|sms\s?code|2fa|mfa|two[\s-]?factor)/i.test(readable);
    const pushApprovalPattern = /(?:approve|allow|accept|authorize|tap).{0,60}(?:login|sign[\s-]?in|push|notification|authenticator|device|session)|(?:push|authenticator|device|session).{0,60}(?:approve|allow|accept|authorize)/i.test(readable);
    const recoveryCodePattern = /(?:backup|recovery|device).{0,35}code.{0,80}(?:send|share|enter|provide|submit|save|verify|restore|recover)|(?:restore|recover).{0,80}(?:backup|recovery|device).{0,35}code/i.test(readable);
    const spacedOtpPattern = /(?:\bo\s*[.\-]?\s*t\s*[.\-]?\s*p\b|one\s*time\s*(?:pass\s*code|passcode|number)|verification\s*(?:number|pass\s*code|passcode)|(?:6|six)\s*[- ]?\s*digit\s*(?:code|number|pin)?)/i.test(readable);
    const expandedCodeHarvestPattern = codeHarvestPattern || spacedOtpPattern || /(?:send|share|enter|provide|submit|reply|forward|copy|paste).{0,80}(?:(?:6|six)\s*[- ]?\s*digit|verification\s*(?:number|pass\s*code|passcode)|o\s*[.\-]?\s*t\s*[.\-]?\s*p)/i.test(readable);
    const density = intent.length + actions.length + context.length + pressure.length + Math.min(3, msgPressure.length) + (expandedCodeHarvestPattern?4:0) + (pushApprovalPattern?3:0) + (recoveryCodePattern?3:0) + mismatchedBrands.length;
    const active = !trusted && (
      ((expandedCodeHarvestPattern || pushApprovalPattern || recoveryCodePattern) && (actions.length || context.length || pressure.length || msgPressure.length || visibleBrands.length || mismatchedBrands.length)) ||
      (intent.length >= 1 && actions.length >= 1 && (context.length || pressure.length || msgPressure.length || mismatchedBrands.length)) ||
      (mismatchedBrands.length && intent.length && (actions.length || context.length)) ||
      density >= 7
    );
    const high = expandedCodeHarvestPattern || pushApprovalPattern || recoveryCodePattern || mismatchedBrands.length || (intent.length >= 2 && actions.length >= 2) || density >= 10;
    const severity = high ? "high" : "medium";
    const weight = high ? 22 : 11;
    return {active, severity, weight, intent, actions, context, pressure, codeHarvestPattern: expandedCodeHarvestPattern, pushApprovalPattern, recoveryCodePattern, spacedOtpPattern, visibleBrands, mismatchedBrands, trusted, density};
  }

  function inspectAccountRecoveryTakeover(target, messageContext){
    const raw = String((target && (target.sourceRaw || target.raw || target.href)) || "");
    const path = String((target && target.path) || "");
    const host = String((target && target.host) || "");
    const decoded = safeDecodeForInspection(raw + " " + path);
    const normalized = (raw + " " + decoded + " " + host + " " + path).toLowerCase().replace(/[\s_]+/g,"-");
    const readable = (raw + " " + decoded + " " + host + " " + path).toLowerCase();
    const trusted = target && target.root && matchingTrustedFamily(target.root);
    const msgPressure = (messageContext && messageContext.pressure) || [];
    const mismatchedBrands = (messageContext && messageContext.mismatchedBrands) || [];
    const visibleBrands = (messageContext && messageContext.visibleBrandHints) || [];
    const intent = Array.from(accountRecoveryIntentWords).filter(word => normalized.includes(word));
    const actions = Array.from(accountRecoveryActionWords).filter(word => normalized.includes(word));
    const context = Array.from(accountRecoveryContextWords).filter(word => normalized.includes(word));
    const pressure = Array.from(accountRecoveryPressureWords).filter(word => normalized.includes(word));
    const passwordResetPattern = /(?:reset|change|restore|recover).{0,45}(?:password|passcode|login|account)|(?:password|login|account).{0,45}(?:reset|change|restore|recover)/i.test(readable);
    const recoveryLinkPattern = /(?:recovery|restore|reactivate|unlock).{0,45}(?:link|account|access|profile)|(?:use|follow|open|click).{0,45}(?:recovery|reset|unlock|reactivation).{0,35}(?:link|button|page)/i.test(readable);
    const changeAlertPattern = /(?:email|phone|device|session|password).{0,45}(?:changed|change|updated|reset|removed|added)|(?:new|unknown|unrecognized).{0,35}(?:device|login|session|sign-in|signin)/i.test(readable);
    const density = intent.length + actions.length + context.length + pressure.length + Math.min(3, msgPressure.length) + (passwordResetPattern?4:0) + (recoveryLinkPattern?3:0) + (changeAlertPattern?3:0) + mismatchedBrands.length;
    const active = !trusted && (
      ((passwordResetPattern || recoveryLinkPattern || changeAlertPattern) && (actions.length || context.length || pressure.length || msgPressure.length || visibleBrands.length || mismatchedBrands.length)) ||
      (intent.length >= 1 && actions.length >= 1 && (context.length || pressure.length || msgPressure.length || mismatchedBrands.length)) ||
      (mismatchedBrands.length && intent.length && (actions.length || context.length)) ||
      density >= 7
    );
    const high = passwordResetPattern || recoveryLinkPattern || changeAlertPattern || mismatchedBrands.length || (intent.length >= 2 && actions.length >= 2) || density >= 10;
    const severity = high ? "high" : "medium";
    const weight = high ? 21 : 10;
    return {active, severity, weight, intent, actions, context, pressure, passwordResetPattern, recoveryLinkPattern, changeAlertPattern, visibleBrands, mismatchedBrands, trusted, density};
  }

  function inspectUrgencyPressureTactic(target, messageContext){
    const raw = String((target && (target.sourceRaw || target.raw || target.href)) || "");
    const path = String((target && target.path) || "");
    const host = String((target && target.host) || "");
    const decoded = safeDecodeForInspection(raw + " " + path);
    const normalized = (raw + " " + decoded + " " + host + " " + path).toLowerCase().replace(/[\s_]+/g,"-");
    const readable = (raw + " " + decoded + " " + host + " " + path).toLowerCase();
    const trusted = target && target.root && matchingTrustedFamily(target.root);
    const msgPressure = (messageContext && messageContext.pressure) || [];
    const mismatchedBrands = (messageContext && messageContext.mismatchedBrands) || [];
    const visibleBrands = (messageContext && messageContext.visibleBrandHints) || [];
    const pressure = Array.from(urgencyPressureWords).filter(word => normalized.includes(word));
    const actions = Array.from(urgencyActionWords).filter(word => normalized.includes(word));
    const sensitive = Array.from(urgencySensitiveWords).filter(word => normalized.includes(word));
    const countdownPattern = /(?:within\s*(?:24|48)\s*hours?|expires?\s*(?:today|tonight|soon)|before\s*(?:midnight|closing|it\s?expires)|deadline|countdown|last\s?chance)/i.test(readable);
    const fearPressurePattern = /(?:do\s?not\s?ignore|avoid\s*(?:suspension|closure|penalty|legal|collections)|will\s?be\s?(?:locked|blocked|suspended|closed)|final\s?(?:notice|warning)|immediate\s?action\s?required)/i.test(readable);
    const actionNowPattern = /(?:act\s?now|respond\s?now|verify\s?now|confirm\s?now|click\s?now|call\s?now|pay\s?now|update\s?now)/i.test(readable);
    const density = pressure.length + actions.length + sensitive.length + Math.min(3, msgPressure.length) + (countdownPattern?3:0) + (fearPressurePattern?3:0) + (actionNowPattern?2:0) + mismatchedBrands.length;
    const active = !trusted && (
      ((countdownPattern || fearPressurePattern || actionNowPattern) && (actions.length || sensitive.length || msgPressure.length || visibleBrands.length || mismatchedBrands.length)) ||
      (pressure.length >= 2 && actions.length && (sensitive.length || msgPressure.length)) ||
      density >= 7
    );
    const high = fearPressurePattern || countdownPattern || mismatchedBrands.length || sensitive.length >= 3 || density >= 10;
    const severity = high ? "high" : "medium";
    const weight = high ? 16 : 8;
    return {active, severity, weight, pressure, actions, sensitive, countdownPattern, fearPressurePattern, actionNowPattern, visibleBrands, mismatchedBrands, trusted, density};
  }

  // v3.19.5: token-aware matching prevents short payment words like "pay"
  // from firing inside unrelated credential words like "password".
  function hasTokenishWord(haystack, word){
    const source = String(haystack || "").toLowerCase();
    const term = String(word || "").toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (!term) return false;
    return new RegExp("(^|[^a-z0-9])" + term + "([^a-z0-9]|$)", "i").test(source);
  }

  function collectTokenishWords(haystack, words){
    return Array.from(words || []).filter(word => hasTokenishWord(haystack, word));
  }

  function inspectPaymentInvoiceScamIntent(target, messageContext){
    const raw = String((target && (target.sourceRaw || target.raw || target.href)) || "");
    const path = String((target && target.path) || "");
    const host = String((target && target.host) || "");
    const decoded = safeDecodeForInspection(raw + " " + path);
    const normalized = (host + " " + path + " " + raw + " " + decoded).toLowerCase().replace(/[\s_]+/g,"-");
    const visibleBrands = (messageContext && messageContext.visibleBrandHints) || [];
    const mismatchedBrands = (messageContext && messageContext.mismatchedBrands) || [];
    const msgPressure = (messageContext && messageContext.pressure) || [];
    const trusted = target && target.root && matchingTrustedFamily(target.root);
    const paymentIntent = collectTokenishWords(normalized, paymentInvoiceIntentWords);
    const actions = collectTokenishWords(normalized, paymentActionWords);
    const pressure = collectTokenishWords(normalized, paymentPressureWords);
    const sensitive = collectTokenishWords(normalized, paymentSensitiveWords);
    const moneyPattern = /(?:\$|cad|usd|amount|total|balance|fee|charge|payment|refund|invoice|subscription|renewal)/i.test(raw);
    const eTransferPattern = /(?:interac|e[-\s]?transfer|etransfer|zelle|venmo|cash\s?app|paypal)/i.test(raw);
    const failedOrUnauthorized = /(?:unauthorized|unknown|unrecognized|failed|declined|overdue|past[-\s]?due|late|subscription|renewal|refund|chargeback|billing\s?problem|payment\s?method)/i.test(raw);
    const density = paymentIntent.length + actions.length + pressure.length + sensitive.length + Math.min(3, msgPressure.length) + (moneyPattern?1:0) + (eTransferPattern?2:0) + (failedOrUnauthorized?2:0) + mismatchedBrands.length;
    const active = !trusted && (
      (paymentIntent.length >= 2 && (actions.length || pressure.length || sensitive.length || msgPressure.length || failedOrUnauthorized)) ||
      (eTransferPattern && (actions.length || pressure.length || visibleBrands.length || failedOrUnauthorized)) ||
      (failedOrUnauthorized && paymentIntent.length && (actions.length || sensitive.length || msgPressure.length)) ||
      (mismatchedBrands.length && paymentIntent.length) ||
      density >= 6
    );
    const high = eTransferPattern || failedOrUnauthorized || sensitive.length >= 2 || pressure.length >= 2 || mismatchedBrands.length || density >= 8;
    const severity = high ? "high" : "medium";
    const weight = high ? 22 : 12;
    return {active, severity, weight, paymentIntent, actions, pressure, sensitive, eTransferPattern, failedOrUnauthorized, moneyPattern, visibleBrands, mismatchedBrands, trusted, density};
  }


  function inspectMoneyMovementScamIntent(target, messageContext){
    const raw = String((target && (target.sourceRaw || target.raw || target.href)) || "");
    const path = String((target && target.path) || "");
    const host = String((target && target.host) || "");
    const decoded = safeDecodeForInspection(raw + " " + path);
    const normalized = (host + " " + path + " " + raw + " " + decoded).toLowerCase().replace(/[\s_]+/g,"-");
    const readable = (raw + " " + decoded + " " + host + " " + path).toLowerCase();
    const visibleBrands = (messageContext && messageContext.visibleBrandHints) || [];
    const mismatchedBrands = (messageContext && messageContext.mismatchedBrands) || [];
    const msgPressure = (messageContext && messageContext.pressure) || [];
    const trusted = target && target.root && matchingTrustedFamily(target.root);
    const railWords = collectTokenishWords(normalized, moneyMovementRailWords);
    const actions = collectTokenishWords(normalized, moneyMovementActionWords);
    const pressure = collectTokenishWords(normalized, moneyMovementPressureWords);
    const sensitive = collectTokenishWords(normalized, moneyMovementSensitiveWords);
    const refundDepositPattern = /(?:refund|rebate|deposit|direct[-\s]?deposit|claim[-\s]?payment|receive[-\s]?payment|release[-\s]?(?:funds|payment)|funds[-\s]?release)/i.test(readable);
    const transferRailPattern = /(?:interac|e[-\s]?transfer|etransfer|zelle|venmo|cash\s?app|paypal|wire[-\s]?transfer|bank[-\s]?transfer|send[-\s]?money|money[-\s]?transfer)/i.test(readable);
    const recipientPattern = /(?:recipient|payee|sender|remittance|beneficiary|security[-\s]?question|answer[-\s]?question|payment[-\s]?password)/i.test(readable);
    const verificationPattern = /(?:verify|confirm|validate|authorize|approve|update).{0,35}(?:payment|deposit|transfer|recipient|bank|card|method|transaction|funds)/i.test(readable);
    const reversalPattern = /(?:unauthorized|unknown|unrecognized|reverse|reversal|cancel|dispute|chargeback|fraud[-\s]?alert|security[-\s]?hold).{0,45}(?:payment|transfer|charge|deposit|transaction)/i.test(readable);
    const hasMoneyMovementCore = transferRailPattern || refundDepositPattern || recipientPattern || reversalPattern || railWords.length || /\b(payment|deposit|transfer|bank|card|method|transaction|funds|money|refund|rebate|wire|e-transfer|interac|zelle|venmo|paypal)\b/i.test(readable);
    const density = railWords.length + actions.length + pressure.length + sensitive.length + Math.min(3, msgPressure.length) + (refundDepositPattern?2:0) + (transferRailPattern?3:0) + (recipientPattern?1:0) + (verificationPattern?2:0) + (reversalPattern?2:0) + mismatchedBrands.length;
    const active = !trusted && hasMoneyMovementCore && (
      (transferRailPattern && (actions.length || pressure.length || sensitive.length || recipientPattern || verificationPattern || msgPressure.length)) ||
      (refundDepositPattern && (actions.length || sensitive.length || pressure.length || visibleBrands.length || msgPressure.length)) ||
      (verificationPattern && (railWords.length || sensitive.length || mismatchedBrands.length)) ||
      (reversalPattern && (actions.length || sensitive.length || pressure.length || railWords.length)) ||
      (mismatchedBrands.length && (railWords.length || refundDepositPattern || transferRailPattern)) ||
      density >= 7
    );
    const high = transferRailPattern || reversalPattern || sensitive.length >= 2 || pressure.length >= 2 || mismatchedBrands.length || density >= 9;
    const severity = high ? "high" : "medium";
    const weight = high ? 24 : 13;
    return {active, severity, weight, railWords, actions, pressure, sensitive, refundDepositPattern, transferRailPattern, recipientPattern, verificationPattern, reversalPattern, visibleBrands, mismatchedBrands, trusted, density};
  }

  function inspectGiftPrizeRewardScamIntent(target, messageContext){
    const raw = String((target && (target.sourceRaw || target.raw || target.href)) || "");
    const path = String((target && target.path) || "");
    const host = String((target && target.host) || "");
    const decoded = safeDecodeForInspection(raw + " " + path);
    const normalized = (host + " " + path + " " + raw + " " + decoded).toLowerCase().replace(/[\s_]+/g,"-");
    const readable = (raw + " " + decoded + " " + host + " " + path).toLowerCase();
    const visibleBrands = (messageContext && messageContext.visibleBrandHints) || [];
    const mismatchedBrands = (messageContext && messageContext.mismatchedBrands) || [];
    const msgPressure = (messageContext && messageContext.pressure) || [];
    const trusted = target && target.root && matchingTrustedFamily(target.root);
    const intent = Array.from(giftPrizeRewardIntentWords).filter(word => normalized.includes(word));
    const actions = Array.from(giftPrizeRewardActionWords).filter(word => normalized.includes(word));
    const pressure = Array.from(giftPrizeRewardPressureWords).filter(word => normalized.includes(word));
    const sensitive = Array.from(giftPrizeRewardSensitiveWords).filter(word => normalized.includes(word));
    const giftCardPurchasePattern = /(?:buy|purchase|send|upload|provide|scratch|share|enter).{0,45}(?:gift[-\s]?card|prepaid[-\s]?card|voucher|steam|apple|google[-\s]?play|itunes|visa[-\s]?gift|mastercard[-\s]?gift)/i.test(readable);
    const prizeClaimPattern = /(?:congratulations|winner|you[-\s]?won|selected|prize|reward|giveaway|sweepstakes|lottery).{0,55}(?:claim|redeem|verify|confirm|activate|collect|release)/i.test(readable);
    const loyaltyPointsPattern = /(?:points|loyalty|airmiles|aeroplan|scene|pc[-\s]?optimum|reward).{0,50}(?:expire|expired|claim|redeem|verify|confirm|bonus|pending)/i.test(readable);
    const feeToClaimPattern = /(?:pay|fee|shipping|handling|activation|processing|release).{0,45}(?:claim|prize|reward|gift|voucher|points|bonus)/i.test(readable);
    const density = intent.length + actions.length + pressure.length + sensitive.length + Math.min(3, msgPressure.length) + (giftCardPurchasePattern?3:0) + (prizeClaimPattern?2:0) + (loyaltyPointsPattern?2:0) + (feeToClaimPattern?2:0) + mismatchedBrands.length;
    const active = !trusted && (
      (giftCardPurchasePattern && (actions.length || pressure.length || sensitive.length || visibleBrands.length || msgPressure.length)) ||
      (prizeClaimPattern && (actions.length || sensitive.length || pressure.length || msgPressure.length)) ||
      (loyaltyPointsPattern && (actions.length || pressure.length || sensitive.length || mismatchedBrands.length)) ||
      (feeToClaimPattern && (intent.length || actions.length || sensitive.length)) ||
      (mismatchedBrands.length && intent.length) ||
      density >= 7
    );
    const high = giftCardPurchasePattern || prizeClaimPattern || feeToClaimPattern || sensitive.length >= 2 || pressure.length >= 2 || mismatchedBrands.length || density >= 9;
    const severity = high ? "high" : "medium";
    const weight = high ? 23 : 12;
    return {active, severity, weight, intent, actions, pressure, sensitive, giftCardPurchasePattern, prizeClaimPattern, loyaltyPointsPattern, feeToClaimPattern, visibleBrands, mismatchedBrands, trusted, density};
  }



  function inspectSubscriptionRenewalScamIntent(target, messageContext){
    const raw = String((target && (target.sourceRaw || target.raw || target.href)) || "");
    const path = String((target && target.path) || "");
    const host = String((target && target.host) || "");
    const decoded = safeDecodeForInspection(raw + " " + path);
    const normalized = (host + " " + path + " " + raw + " " + decoded).toLowerCase().replace(/[\s_]+/g,"-");
    const readable = (raw + " " + decoded + " " + host + " " + path).toLowerCase();
    const visibleBrands = (messageContext && messageContext.visibleBrandHints) || [];
    const mismatchedBrands = (messageContext && messageContext.mismatchedBrands) || [];
    const msgPressure = (messageContext && messageContext.pressure) || [];
    const trusted = target && target.root && matchingTrustedFamily(target.root);
    const intent = Array.from(subscriptionRenewalIntentWords).filter(word => normalized.includes(word));
    const actions = Array.from(subscriptionRenewalActionWords).filter(word => normalized.includes(word));
    const pressure = Array.from(subscriptionRenewalPressureWords).filter(word => normalized.includes(word));
    const sensitive = Array.from(subscriptionRenewalSensitiveWords).filter(word => normalized.includes(word));
    const billingFailedPattern = /(?:billing|payment|card|invoice|charge).{0,45}(?:failed|declined|problem|issue|overdue|past[-\s]?due|update|required)/i.test(readable);
    const expiryCancelPattern = /(?:subscription|membership|plan|account|service|license|licence|domain|storage).{0,55}(?:expire|expires|expired|expiring|cancel|cancelled|canceled|suspend|suspended|terminated|locked)/i.test(readable);
    const renewalActionPattern = /(?:renew|reactivate|restore|continue|keep|avoid[-\s]?loss|update[-\s]?payment|update[-\s]?card|confirm[-\s]?billing|verify[-\s]?payment)/i.test(readable);
    const domainHostingPattern = /(?:domain|hosting|ssl|mailbox|email|website).{0,55}(?:renewal|expire|expires|expired|suspend|payment|billing|verify|update)/i.test(readable);
    const density = intent.length + actions.length + pressure.length + sensitive.length + Math.min(3, msgPressure.length) + (billingFailedPattern?3:0) + (expiryCancelPattern?2:0) + (renewalActionPattern?2:0) + (domainHostingPattern?2:0) + mismatchedBrands.length;
    const active = !trusted && (
      (billingFailedPattern && (actions.length || pressure.length || sensitive.length || msgPressure.length)) ||
      (expiryCancelPattern && (actions.length || pressure.length || sensitive.length || visibleBrands.length || msgPressure.length)) ||
      (renewalActionPattern && intent.length && (pressure.length || sensitive.length || mismatchedBrands.length || msgPressure.length)) ||
      (domainHostingPattern && (actions.length || pressure.length || sensitive.length)) ||
      (mismatchedBrands.length && intent.length) ||
      density >= 7
    );
    const high = billingFailedPattern || expiryCancelPattern || domainHostingPattern || sensitive.length >= 2 || pressure.length >= 2 || mismatchedBrands.length || density >= 9;
    const severity = high ? "high" : "medium";
    const weight = high ? 24 : 12;
    return {active, severity, weight, intent, actions, pressure, sensitive, billingFailedPattern, expiryCancelPattern, renewalActionPattern, domainHostingPattern, visibleBrands, mismatchedBrands, trusted, density};
  }

  function inspectAttachmentFileTrapIntent(target, messageContext){
    const raw = String((target && (target.sourceRaw || target.raw || target.href)) || "");
    const path = String((target && target.path) || "");
    const host = String((target && target.host) || "");
    const decoded = safeDecodeForInspection(raw + " " + path);
    const normalized = (raw + " " + decoded + " " + host + " " + path).toLowerCase().replace(/[^a-z0-9.]+/g, "-");
    const readable = (raw + " " + decoded + " " + host + " " + path).toLowerCase();
    const fileIntent = Array.from(attachmentFileIntentWords).filter(word => normalized.includes(word));
    const actions = Array.from(attachmentActionWords).filter(word => normalized.includes(word));
    const cloudBrands = Array.from(attachmentCloudBrandWords).filter(word => normalized.includes(word));
    const macroWords = Array.from(attachmentMacroWords).filter(word => normalized.includes(word));
    const pressure = Array.from(attachmentPressureWords).filter(word => normalized.includes(word));
    const visibleBrands = (messageContext && messageContext.visibleBrandHints) || [];
    const mismatchedBrands = (messageContext && messageContext.mismatchedBrands) || [];
    const messagePressure = (messageContext && messageContext.pressure) || [];
    const directOfficeOrPdf = pathHasExtension(readable, [".pdf",".doc",".docx",".xls",".xlsx",".ppt",".pptx",".rtf",".csv"]).slice(0,6);
    const archiveHits = pathHasExtension(readable, compressedDeliveryExtensions).slice(0,6);
    const executableHits = pathHasExtension(readable, riskyExtensions).slice(0,6);
    const hasAttachmentAction = fileIntent.length && (actions.length || cloudBrands.length || directOfficeOrPdf.length || archiveHits.length || executableHits.length);
    const lureDensity = fileIntent.length + actions.length + cloudBrands.length + macroWords.length + pressure.length + Math.min(3, messagePressure.length) + directOfficeOrPdf.length + archiveHits.length + executableHits.length;
    const trusted = target && target.type === "url" ? isKnownRoot(target) : false;
    const trustedBenignCloudFile = trusted && !macroWords.length && !executableHits.length && !archiveHits.length && !mismatchedBrands.length && !pressure.length && !messagePressure.length && cloudBrands.length && (directOfficeOrPdf.length || fileIntent.length || /\/(file|document|docs|scl|share|shared)\//i.test(path));
    const active = trustedBenignCloudFile ? false : (macroWords.length || executableHits.length || (hasAttachmentAction && (pressure.length || messagePressure.length || visibleBrands.length || cloudBrands.length || archiveHits.length || directOfficeOrPdf.length)) || lureDensity >= 5);
    let severity = "low";
    let weight = 4;
    if (active && (macroWords.length || executableHits.length || archiveHits.length || mismatchedBrands.length || (cloudBrands.length && !trusted) || lureDensity >= 7)) { severity = "high"; weight = 22; }
    else if (active) { severity = "medium"; weight = 12; }
    return {active, severity, weight, fileIntent, actions, cloudBrands, macroWords, pressure, directOfficeOrPdf, archiveHits, executableHits, visibleBrands, mismatchedBrands, trusted, lureDensity, trustedBenignCloudFile};
  }

  function hasEncodedAtOrSlashTrick(raw){
    const value = String(raw || "");
    return /%40/i.test(value) || /%2f%2f/i.test(value) || /\\/.test(value);
  }

  function hasAuthorityConfusion(raw){
    const value = String(raw || "");
    return /\\+@/.test(value) || /@[^\s/]+\.[a-z]{2,}/i.test(value) || /%5c/i.test(value) || /%40/i.test(value);
  }


  function hasDoubleEncodedSeparator(raw){
    const value = String(raw || "");
    const once = safeDecodeForInspection(value);
    return /%25(2e|2f|5c|40|3a)/i.test(value) || /%(2e|2f|5c|40|3a)/i.test(once);
  }

  function isPrivateOrLocalHost(host){
    const h = String(host || "").toLowerCase().replace(/^\[|\]$/g, "");
    if (!h) return false;
    if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal") || h.endsWith(".lan")) return true;
    if (h === "::1" || h.startsWith("fe80:") || h.startsWith("fc") || h.startsWith("fd")) return true;
    const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) return false;
    const a = Number(m[1]), b = Number(m[2]);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31);
  }

  function isKnownShortenerRoot(root){
    return shorteners.has(String(root || "").toLowerCase());
  }

  function isRelayWrapperTarget(target){
    const root = String((target && target.root) || "").toLowerCase();
    const host = String((target && target.host) || "").toLowerCase();
    const path = String((target && target.path) || "").toLowerCase().split("?")[0];
    if (!root || !target || target.type !== "url") return false;
    if (root === "google.com" && path === "/url") return true;
    if (host === "l.facebook.com" && path === "/l.php") return true;
    if (host === "lm.facebook.com" && path === "/l.php") return true;
    if ((root === "linkedin.com" || root === "twitter.com" || root === "x.com") && relayPathHints.some(h => path === h || path.startsWith(h + "/"))) return true;
    if (relayRoots.has(root) && relayPathHints.some(h => path === h || path.startsWith(h + "/"))) return true;
    if (/urldefense|safelinks|proofpoint|mandrill|sendgrid|mailchimp|list-manage|hubspotlinks|clickdimensions|emltrk/i.test(host)) return true;
    return false;
  }

  function hasSensitiveBrandContext(messageContext){
    if (!messageContext) return false;
    return (messageContext.visibleBrandHints && messageContext.visibleBrandHints.length > 0) || (messageContext.pressure && messageContext.pressure.length >= 2);
  }

  function findRedirectDestinationRoots(target){
    const url = parsedUrlForTarget(target);
    const roots = [];
    if (!url) return roots;
    url.searchParams.forEach((value, key) => {
      const name = String(key || "").toLowerCase().replace(/[^a-z0-9_:-]/g, "");
      const compactName = name.replace(/[^a-z0-9]/g, "");
      const googleOutboundQ = target.root === "google.com" && String(url.pathname || "").toLowerCase() === "/url" && (name === "q" || compactName === "q");
      if (!(redirectParamNames.has(name) || redirectParamNames.has(compactName) || googleOutboundQ)) return;
      const decoded = safeDecodeForInspection(value);
      const candidates = extractCandidateUrls(decoded);
      candidates.forEach(candidate => {
        try {
          const candidateUrl = new URL(/^https?:\/\//i.test(candidate) ? candidate : "https://" + candidate.replace(/^www\./i,"www."));
          const host = candidateUrl.hostname.replace(/\.$/, "").toLowerCase();
          roots.push({param:name || key, host, root:getRootDomain(host), href:candidateUrl.href, path:(candidateUrl.pathname || "/") + (candidateUrl.search || "")});
        } catch(error) {}
      });
    });
    const seen = new Set();
    return roots.filter(item => { const k = item.param + "|" + item.root; if (seen.has(k)) return false; seen.add(k); return true; });
  }


  function classifyRedirectIntent(target, messageContext, redirectRoots, queryFindings){
    const raw = String((target && (target.sourceRaw || target.raw)) || "");
    const root = String((target && target.root) || "").toLowerCase();
    const roots = Array.isArray(redirectRoots) ? redirectRoots.filter(item => item && item.root) : [];
    const redirectParams = (queryFindings && queryFindings.redirect) || [];
    const redirectishRaw = /\b(redirect|redir|continue|returnurl|return_to|destination|target|goto|safelink|urldefense|outbound|relay|tracking)\b/i.test(raw);
    const hasRedirect = roots.length > 0 || redirectParams.length > 0 || redirectishRaw || isRelayWrapperTarget(target) || isKnownShortenerRoot(root);
    if (!target || target.type !== "url" || !hasRedirect) return {active:false};

    const startingTrusted = trustedRoots.has(root) || !!matchingTrustedFamily(root);
    const crossRoot = roots.filter(item => item.root && item.root !== root);
    const externalUntrusted = crossRoot.filter(item => !(trustedRoots.has(item.root) || matchingTrustedFamily(item.root)));
    const trustedEmbedded = crossRoot.filter(item => trustedRoots.has(item.root) || matchingTrustedFamily(item.root));
    const msgPressure = (messageContext && messageContext.pressure) || [];
    const msgMismatch = (messageContext && messageContext.mismatchedBrands && messageContext.mismatchedBrands.length) || false;
    const allRedirectText = (raw + " " + roots.map(item => (item.root || "") + " " + (item.path || "")).join(" ")).toLowerCase();
    const credentialRedirect = Array.from(credentialIntentWords).some(word => allRedirectText.includes(word)) || Array.from(credentialCollectionWords).some(word => allRedirectText.includes(word));
    const financialRedirect = Array.from(credentialFinancialWords).some(word => allRedirectText.includes(word));
    const wrapper = isRelayWrapperTarget(target) || isKnownShortenerRoot(root);
    const sameRootOnly = roots.length > 0 && roots.every(item => item.root === root);

    if (sameRootOnly && startingTrusted && !msgMismatch && msgPressure.length < 2) {
      return {active:true, severity:"low", title:"First-party redirect intent", detail:"v2.67 classified the redirect as first-party because the embedded destination stays on the same known root. It is recorded as context instead of treated as a hostile handoff.", weight:-1, mode:"first-party"};
    }

    if (externalUntrusted.length && (startingTrusted || msgMismatch || credentialRedirect || financialRedirect || msgPressure.length >= 2)) {
      const readable = externalUntrusted.slice(0,3).map(item => item.param + "→" + item.root).join(", ");
      return {active:true, severity:"high", title:"Redirect intent classifier: sensitive external handoff", detail:"v2.67 found redirect behavior that moves from a trusted/credential/pressure context toward an external untrusted root: " + readable + ". Treat the starting page and final destination as one chain, not as separate harmless links.", weight:22, mode:"sensitive-external"};
    }

    if (trustedEmbedded.length && !startingTrusted) {
      const readable = trustedEmbedded.slice(0,3).map(item => item.param + "→" + item.root).join(", ");
      return {active:true, severity:"high", title:"Redirect intent classifier: trusted brand lure", detail:"v2.67 found an untrusted starting root carrying a redirect toward a known trusted family: " + readable + ". This can be used to make the link look safer than the first controlling domain really is.", weight:18, mode:"trusted-lure"};
    }

    if (crossRoot.length && wrapper && (msgPressure.length || credentialRedirect || financialRedirect)) {
      const readable = crossRoot.slice(0,3).map(item => item.param + "→" + item.root).join(", ");
      return {active:true, severity:"high", title:"Redirect intent classifier: wrapper with sensitive context", detail:"v2.67 found a relay/shortener wrapper plus sensitive or pressure context. Observed handoff: " + readable + ". Verify the final root before entering information.", weight:18, mode:"wrapper-sensitive"};
    }

    if (crossRoot.length) {
      const readable = crossRoot.slice(0,3).map(item => item.param + "→" + item.root).join(", ");
      return {active:true, severity:"medium", title:"Redirect intent classifier: cross-root handoff", detail:"v2.67 classified the link as a cross-root handoff: " + readable + ". This may be legitimate, but the final destination must be judged separately from the visible starting link.", weight:10, mode:"cross-root"};
    }

    if ((redirectParams.length || redirectishRaw) && !roots.length && (credentialRedirect || msgPressure.length >= 2 || msgMismatch)) {
      return {active:true, severity:"medium", title:"Redirect intent classifier: opaque redirect parameter", detail:"v2.67 found redirect-style parameters but could not extract a readable final URL. Because the surrounding context is sensitive, treat the link as needs-review until the destination is verified.", weight:10, mode:"opaque-sensitive"};
    }

    if (wrapper) {
      return {active:true, severity:"medium", title:"Redirect intent classifier: wrapper boundary", detail:"v2.67 classified this as a relay, shortener, or tracking wrapper. Offline Proxuma does not expand it automatically, so the final destination remains unverified.", weight:6, mode:"wrapper"};
    }

    return {active:false};
  }

  function hasParserControlCharacters(raw){
    const value = String(raw || "");
    return /[\u0000-\u001F\u007F]/.test(value) || /%(00|0d|0a|09)/i.test(value);
  }

  function findLookalikeSecurityWords(text){
    const hits = [];
    const seen = new Set();
    const inspectionText = String(text || "") + " " + safeDecodeForInspection(text);
    tokenizeForMatch(inspectionText).forEach(token => {
      if (!/[01345@$]/.test(token) || token.length < 4) return;
      const variants = [normalizeLookalikeToken(token, "i"), normalizeLookalikeToken(token, "l")];
      variants.forEach(normalized => {
        if (normalized !== token && sensitiveLookalikeWords.has(normalized)) {
          const key = token + "→" + normalized;
          if (!seen.has(key)) { seen.add(key); hits.push({token, normalized}); }
        }
      });
    });
    return hits;
  }
  function normalizeAliasCompact(value){
    return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, "");
  }
  function findLookalikeInstitutionDomains(host, path, root){
    const hits = [];
    const seen = new Set();
    const rawHost = String(host || "").toLowerCase();
    const rawRoot = String(root || "").toLowerCase();
    const rawPath = String(path || "").toLowerCase();
    const rawText = (rawHost + " " + rawPath + " " + safeDecodeForInspection(rawPath)).trim();
    const tokenCandidates = tokenizeForMatch(rawText).filter(token => /[01345@$]/.test(token) && token.length >= 4);
    const rootVariants = [normalizeLookalikeToken(rawRoot, "i"), normalizeLookalikeToken(rawRoot, "l")];

    brandFamilies.forEach(family => {
      rootVariants.forEach(normalizedRoot => {
        const trustedRootHit = family.roots.find(officialRoot => normalizedRoot === officialRoot && rawRoot !== officialRoot);
        if (trustedRootHit) {
          const key = family.name + "|" + rawRoot + "|" + trustedRootHit;
          if (!seen.has(key)) {
            seen.add(key);
            hits.push({family: family.name, observed: rawRoot || rawHost, normalized: trustedRootHit});
          }
        }
      });

      tokenCandidates.forEach(token => {
        const tokenVariants = [normalizeLookalikeToken(token, "i"), normalizeLookalikeToken(token, "l")];
        tokenVariants.forEach(normalizedToken => {
          if (normalizedToken === token) return;
          const aliasHit = family.aliases.find(alias => {
            const compactAlias = normalizeAliasCompact(alias);
            if (!compactAlias || compactAlias.length <= 3) return false;
            return normalizedToken.includes(compactAlias);
          });
          if (aliasHit) {
            const key = family.name + "|" + token + "|" + aliasHit;
            if (!seen.has(key)) {
              seen.add(key);
              hits.push({family: family.name, observed: token, normalized: aliasHit});
            }
          }
        });
      });
    });
    return hits;
  }

  function findBrandMentions(host, path){
    const text = (host + " " + path).toLowerCase();
    return brandFamilies.filter(f => f.aliases.some(a => aliasMatches(text, a)));
  }

  function findTrustedHintsInVisibleText(text){
    const raw = String(text || "").toLowerCase();
    if (!raw) return [];
    const compact = raw.replace(/[^a-z0-9.]+/g, "");
    const hits = [];
    brandFamilies.forEach(family => {
      const rootHit = family.roots.find(root => root.length > 5 && (raw.includes(root) || compact.includes(root.replace(/[^a-z0-9.]/g, ""))));
      const protectedShort = new Set(["rbc","td","bmo","cibc","pnc","bofa","amex","ups","dhl"]);
      const aliasHit = family.aliases.find(alias => (alias.length >= 4 || protectedShort.has(alias.toLowerCase())) && aliasMatches(raw, alias));
      if (rootHit || aliasHit) hits.push({family:family.name, hint:rootHit || aliasHit});
    });
    return hits;
  }

  function findShortInstitutionPressureDomains(host, path, root){
    const hits = [];
    const seen = new Set();
    const rawHost = String(host || "").toLowerCase();
    const rawRoot = String(root || "").toLowerCase();
    const rawPath = String(path || "").toLowerCase();
    const tokens = tokenizeForMatch(rawHost + " " + rawRoot).filter(token => token.length >= 5);
    const pathTokens = tokenizeForMatch(rawPath);
    const shortProtected = [
      {alias:"rbc", family:"RBC / Royal Bank", requireBank:false},
      {alias:"td", family:"TD / TD Bank", requireBank:true},
      {alias:"bmo", family:"BMO / Bank of Montreal", requireBank:false},
      {alias:"cibc", family:"CIBC", requireBank:false},
      {alias:"pnc", family:"PNC Bank", requireBank:false},
      {alias:"bofa", family:"Bank of America", requireBank:false},
      {alias:"amex", family:"American Express", requireBank:false},
      {alias:"nfcu", family:"Navy Federal Credit Union", requireBank:false}
    ];
    const sensitiveRoots = Array.from(sensitiveLookalikeWords).concat(["bank","banking","easyweb","signin","signon","card","credit"]);
    tokens.forEach(token => {
      const variants = Array.from(new Set([token, normalizeLookalikeToken(token, "i"), normalizeLookalikeToken(token, "l")]));
      shortProtected.forEach(item => {
        variants.forEach(normalized => {
          if (!normalized.startsWith(item.alias) || normalized === item.alias) return;
          const remainder = normalized.slice(item.alias.length);
          const hasSensitiveRemainder = sensitiveRoots.some(word => remainder.includes(word) || normalized.includes(word));
          const hasSensitiveNearby = pathTokens.some(p => sensitiveRoots.includes(normalizeLookalikeToken(p, "i")) || sensitiveRoots.includes(normalizeLookalikeToken(p, "l")));
          const tdAllowed = !item.requireBank || /^(bank|canadatrust|easyweb|secure|login|signin|verify|account)/.test(remainder);
          if ((hasSensitiveRemainder || hasSensitiveNearby) && tdAllowed) {
            const key = item.family + "|" + token + "|" + normalized;
            if (!seen.has(key)) {
              seen.add(key);
              hits.push({family:item.family, observed:token, normalized:item.alias, clue:hasSensitiveRemainder ? remainder : "path context"});
            }
          }
        });
      });
    });
    return hits;
  }

  function levenshteinDistance(a, b){
    a = String(a || ""); b = String(b || "");
    if (Math.abs(a.length - b.length) > 2) return 99;
    const row = Array.from({length:b.length + 1}, (_, i) => i);
    for (let i = 1; i <= a.length; i++) {
      let prev = row[0]; row[0] = i;
      for (let j = 1; j <= b.length; j++) {
        const temp = row[j];
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        row[j] = Math.min(row[j] + 1, row[j - 1] + 1, prev + cost);
        prev = temp;
      }
    }
    return row[b.length];
  }

  function compactRootName(value){
    return String(value || "").toLowerCase().replace(/^www\./, "").split(".")[0].replace(/[^a-z0-9]/g, "");
  }

  function findNearMissInstitutionRoot(root){
    const observed = compactRootName(root);
    if (!observed || observed.length < 5) return [];
    const hits = [];
    const seen = new Set();
    brandFamilies.forEach(family => {
      const candidates = [];
      family.roots.forEach(r => candidates.push(compactRootName(r)));
      family.aliases.forEach(a => {
        const c = normalizeAliasCompact(a);
        if (c.length >= 5) candidates.push(c);
      });
      Array.from(new Set(candidates)).forEach(candidate => {
        if (!candidate || candidate.length < 5 || observed === candidate) return;
        const dist = levenshteinDistance(observed, candidate);
        const containsOfficial = observed.includes(candidate) || candidate.includes(observed);
        const suspiciouslyClose = dist === 1 || (dist === 2 && candidate.length >= 9) || (containsOfficial && observed !== candidate && observed.length >= candidate.length + 2);
        if (!suspiciouslyClose) return;
        const key = family.name + "|" + observed + "|" + candidate;
        if (!seen.has(key)) { seen.add(key); hits.push({family: family.name, observed, expected:candidate, distance:dist}); }
      });
    });
    return hits;
  }

  function shannonEntropy(value){
    const text = String(value || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    if (!text) return 0;
    const counts = {};
    for (const ch of text) counts[ch] = (counts[ch] || 0) + 1;
    return Object.values(counts).reduce((sum, count) => {
      const p = count / text.length;
      return sum - (p * Math.log2(p));
    }, 0);
  }

  function findRandomizedRootPattern(root){
    const label = compactRootName(root);
    if (label.length < 12) return null;
    const entropy = shannonEntropy(label);
    const digitCount = (label.match(/\d/g) || []).length;
    const vowelCount = (label.match(/[aeiou]/g) || []).length;
    const consonantRun = (label.match(/[bcdfghjklmnpqrstvwxyz]{5,}/g) || [""])[0].length;
    const mixed = /[a-z]/.test(label) && /\d/.test(label);
    const strange = entropy >= 3.45 && (consonantRun >= 5 || digitCount >= 3 || (mixed && vowelCount <= 2));
    return strange ? {label, entropy:Number(entropy.toFixed(2)), digitCount, consonantRun} : null;
  }

  function findSuspiciousPathKit(path){
    const clean = String(path || "").toLowerCase().split(/[?#]/)[0];
    const segments = clean.split("/").filter(Boolean).map(part => safeDecodeForInspection(part).toLowerCase());
    if (segments.length < 3) return null;
    const folderHits = segments.filter(seg => suspiciousPathFolders.has(seg) || Array.from(suspiciousPathFolders).some(word => seg.includes(word)));
    const fileHit = segments.find(seg => suspiciousFileNames.has(seg));
    const workflowHits = Array.from(highValueWorkflowWords).filter(word => clean.includes(word));
    const deep = segments.length >= 5;
    if ((folderHits.length >= 3 && (fileHit || workflowHits.length >= 2)) || (deep && folderHits.length >= 2 && workflowHits.length >= 3)) {
      return {segments:segments.length, folderHits:Array.from(new Set(folderHits)).slice(0,5), fileHit:fileHit || "", workflowHits:workflowHits.slice(0,5)};
    }
    return null;
  }

  function findTrustedBrandRedirectMismatch(target, root){
    const url = parsedUrlForTarget(target);
    if (!url) return [];
    const hits = [];
    url.searchParams.forEach((value, key) => {
      const name = String(key || "").toLowerCase();
      const compactName = name.replace(/[^a-z0-9]/g, "");
      if (!redirectParamNames.has(name) && !redirectParamNames.has(compactName)) return;
      const decoded = safeDecodeForInspection(value);
      const embeddedUrls = decoded.match(/https?:\/\/[^\s&]+/ig) || [];
      embeddedUrls.forEach(item => {
        try {
          const embedded = new URL(item);
          const embeddedRoot = getRootDomain(embedded.hostname.toLowerCase());
          const family = matchingTrustedFamily(embeddedRoot);
          if (family && embeddedRoot !== root) hits.push({param:name || key, embeddedRoot, family:family.name});
        } catch(error) {}
      });
    });
    return hits;
  }


  function findEmbeddedTrustedDomainInPath(host, path, root){
    const decoded = safeDecodeForInspection(String(path || "")).toLowerCase();
    const compact = decoded.replace(/[^a-z0-9.:-]+/g, " ");
    const hits = [];
    const seen = new Set();
    brandFamilies.forEach(family => {
      family.roots.forEach(officialRoot => {
        const obviousEmbed = compact.includes(officialRoot) || compact.includes(officialRoot.replace(/\./g, "-"));
        const urlLikeEmbed = decoded.includes("http://" + officialRoot) || decoded.includes("https://" + officialRoot) || decoded.includes("//" + officialRoot);
        if ((obviousEmbed || urlLikeEmbed) && officialRoot !== root) {
          const key = family.name + "|" + officialRoot;
          if (!seen.has(key)) { seen.add(key); hits.push({family:family.name, officialRoot}); }
        }
      });
    });
    return hits;
  }

  function findTrustedRootStuffedSubdomain(host, root){
    const rootPattern = String(root || "").replace(/\./g,"\\.");
    const prefix = String(host || "").toLowerCase().replace(new RegExp("\\.?" + rootPattern + "$"), "");
    if (!prefix) return [];
    const compactPrefix = prefix.replace(/[^a-z0-9.]+/g, "");
    const hits = [];
    const seen = new Set();
    brandFamilies.forEach(family => {
      family.roots.forEach(officialRoot => {
        const dotted = officialRoot;
        const dashed = officialRoot.replace(/\./g, "-");
        const compact = officialRoot.replace(/\./g, "");
        if ((compactPrefix.includes(dotted) || compactPrefix.includes(dashed) || compactPrefix.replace(/\./g, "").includes(compact)) && officialRoot !== root) {
          const key = family.name + "|" + officialRoot;
          if (!seen.has(key)) { seen.add(key); hits.push({family:family.name, officialRoot}); }
        }
      });
    });
    return hits;
  }

  function isKnownRoot(target){
    if (!target || !target.root) return false;
    const root = target.root;
    return trustedRoots.has(root) || !!matchingTrustedFamily(root);
  }

  function classifyTrustedShareWrapper(target){
    if (!target || target.type !== "url") return {active:false};
    const host = String(target.host || "").toLowerCase();
    const root = String(target.root || "").toLowerCase();
    const path = String(target.path || "/");
    const url = parsedUrlForTarget(target);
    const queryText = url ? String(url.search || "") : "";
    const hasReadableDestination = findRedirectDestinationRoots(target).length > 0 || extractCandidateUrls(queryText).length > 0;
    const isGoogleShare = root === "share.google" || host.endsWith(".share.google");
    if (!isGoogleShare) return {active:false};
    const compactPath = path.replace(/^\/+|\/+$/g, "");
    const opaqueToken = compactPath && /^[a-z0-9_-]{8,}$/i.test(compactPath) && !/[.]/.test(compactPath);
    if (hasReadableDestination) {
      return {active:true, mode:"readable-destination", severity:"low", weight:-1, title:"Trusted share wrapper with readable destination", detail:"v2.71 recognized a Google share wrapper and found a readable destination clue. The final destination should still be checked before trust is granted."};
    }
    if (opaqueToken) {
      return {active:true, mode:"opaque-token", severity:"medium", weight:12, title:"Trusted share wrapper hides final destination", detail:"v2.71 recognized this as a Google-controlled share wrapper, but the visible URL does not reveal the final destination offline. Treat it as review-needed instead of blindly safe or automatically hostile."};
    }
    return {active:true, mode:"unresolved-wrapper", severity:"medium", weight:8, title:"Trusted share wrapper needs destination check", detail:"v2.71 recognized a trusted share-wrapper style link, but the final landing page is not visible to the offline engine. Open only when the source and destination context make sense."};
  }


  function classifySignalFamily(signal){
    const title = String((signal && signal.title) || "").toLowerCase();
    const detail = String((signal && signal.detail) || "").toLowerCase();
    const text = title + " " + detail;
    // v2.87: title-first routing keeps a specific scam classifier from being
    // overshadowed by generic words inside its explanation text.
    if (/^money movement \/ payment rail scam pattern$/.test(title)) return "Money movement scam";
    if (/^gift card \/ prize \/ reward claim scam pattern$/.test(title)) return "Gift/prize scam";
    if (/^subscription \/ account renewal scam pattern$/.test(title)) return "Subscription renewal scam";
    if (/^payment \/ invoice scam pattern$/.test(title)) return "Payment scam";
    if (/^delivery \/ customs scam pattern$/.test(title)) return "Delivery scam";
    if (/^parking \/ toll \/ transit scam pattern$/.test(title)) return "Parking/toll/transit scam";
    if (/^government \/ tax \/ legal threat pattern$/.test(title)) return "Government/legal scam";
    if (/^fake security alert \/ tech support pattern$/.test(title)) return "Fake security alert";
    if (/^job \/ employment scam pattern$/.test(title)) return "Job scam";
    if (/^ai \/ family emergency impersonation pattern$/.test(title)) return "AI emergency scam";
    if (/^social media dm \/ influencer scam pattern$/.test(title)) return "Social DM scam";
    if (/^marketplace buyer-seller scam pattern$/.test(title)) return "Marketplace scam";
    if (/^student \/ school portal scam pattern$/.test(title)) return "Student scam";
    if (/^fake recovery \/ report portal scam pattern$/.test(title)) return "Fake recovery scam";
    if (/^crypto \/ investment scam pattern$/.test(title)) return "Crypto/investment scam";
    if (/^romance \/ trust-building social engineering pattern$/.test(title)) return "Trust/social-engineering scam";
    if (/^attachment \/ file trap intent$/.test(title)) return "File/download trap";
    if (/^callback scam intent pattern$/.test(title)) return "Callback scam";
    if (/^urgency \/ pressure tactic pattern$/.test(title)) return "Urgency / pressure tactic";
    if (/^authority \/ impersonation voice pattern$/.test(title)) return "Authority impersonation";
    if (/^mfa \/ otp code theft pattern$/.test(title)) return "MFA / OTP code theft";
    if (/^account recovery \/ password reset takeover pattern$/.test(title)) return "Account recovery takeover";
    if (/^credential-harvest intent pattern$/.test(title)) return "Credential theft";
    if (/fake security alert|tech support|remote-access|device-infected|virus|malware|account-locked/.test(text)) return "Fake security alert";
    if (/crypto \/ investment|wallet|seed phrase|private key|guaranteed-return|trading-bot|investment scam/.test(text)) return "Crypto/investment scam";
    if (/money movement \/ payment rail|interac|e-transfer|etransfer|zelle|venmo|cash app|bank-transfer|wire-transfer|direct-deposit|refund-deposit|payment-verification|recipient|payee/.test(text)) return "Money movement scam";
    if (/gift card \/ prize \/ reward|gift-card|prepaid-card|voucher|claim-prize|claim-reward|loyalty points|reward points|sweepstakes|giveaway/.test(text)) return "Gift/prize scam";
    if (/subscription \/ account renewal|subscription|renewal|auto-renew|payment-method|billing failed|card declined|domain-renewal|storage full|membership expired/.test(text)) return "Subscription renewal scam";
    if (/payment \/ invoice|billing|invoice|refund|subscription|e-transfer|interac|unauthorized-charge/.test(text)) return "Payment scam";
    if (/credential-harvest|password|otp|one-time|pin|credential/.test(text)) return "Credential theft";
    if (/callback scam|phone|support contact|call this number|callback/.test(text)) return "Callback scam";
    if (/urgency \/ pressure|final-notice|act-now|countdown|fear-pressure/.test(text)) return "Urgency / pressure tactic";
    if (/authority \/ impersonation|official notice|department|case-id|reference-number|compliance|audit|investigation/.test(text)) return "Authority impersonation";
    if (/mfa \/ otp|one-time-code|verification-code|security-code|authenticator|push-approval|2fa|multi-factor/.test(text)) return "MFA / OTP code theft";
    if (/account recovery|password reset|reset-password|recovery-link|account-unlock|email-change|new-device|session-reset/.test(text)) return "Account recovery takeover";
    if (/attachment \/ file trap|shared-document|macro|download|file-opening|risky file|double-extension/.test(text)) return "File/download trap";
    if (/parking \/ toll \/ transit|parking-meter|pay parking|unpaid toll|license-plate|licence-plate|vehicle plate|citation|parking violation|transit fare/.test(text)) return "Parking/toll/transit scam";
    if (/delivery \/ customs|package|parcel|tracking|redelivery|customs|duty/.test(text)) return "Delivery scam";
    if (/government \/ tax \/ legal|tax|benefit|fine|warrant|court|legal threat|government/.test(text)) return "Government/legal scam";
    if (/job \/ employment|recruiter|remote-work|work-from-home|task-job|task platform|onboarding|payroll|equipment-check|reshipping|mystery-shopper|interview/.test(text)) return "Job scam";
    if (/ai \/ family emergency|deepfake|voice-clone|new-number\/family-emergency|cannot-call/.test(text)) return "AI emergency scam";
    if (/social media dm|off-platform dm|influencer|whatsapp|telegram|signal|giveaway\/mentor|verification-badge/.test(text)) return "Social DM scam";
    if (/marketplace buyer-seller|courier\/overpayment|payment-pending|release-funds|shipping agent|buyer-protection|seller-protection/.test(text)) return "Marketplace scam";
    if (/student \/ school|scholarship|tuition|student portal|campus job|school login/.test(text)) return "Student scam";
    if (/fake recovery|report portal|funds-recovery|crypto recovery|recovery agent|case-number|refund investigation/.test(text)) return "Fake recovery scam";
    if (/romance \/ trust-building|move-off-platform|gift-card|emergency-money|private-photo|social engineering/.test(text)) return "Trust/social-engineering scam";
    if (/redirect|shortener|wrapper|relay/.test(text)) return "Redirect/wrapper risk";
    if (/lookalike|near-miss|trusted domain embedded|trusted root stuffed|brand \/ destination mismatch|brand outside verified root/.test(text)) return "Brand/domain impersonation";
    if (/html|form submits|hidden link|meta refresh|javascript redirect/.test(text)) return "Copied HTML trap";
    return "General structure";
  }

  // v3.01: centralized threat lane index. This keeps dominant-threat routing,
  // report wording, severity priority, and next-action language in one stable
  // internal map so future classifiers do not scatter naming/weight rules.
  const THREAT_LANE_INDEX = {
    "Credential theft": {id:"LANE-CRED-001", label:"Login or credential request", priority:88, action:"Do not enter passwords or private account details from the scanned path."},
    "Brand/domain impersonation": {id:"LANE-BRAND-002", label:"Brand or domain impersonation clue", priority:131, action:"Verify the root domain through the official site or app before trusting the brand claim."},
    "File/download trap": {id:"LANE-FILE-003", label:"File, document, or download request", priority:126, action:"Do not open downloads or enable document content until the sender is verified outside the message."},
    "Payment scam": {id:"LANE-PAY-004", label:"Payment or invoice request", priority:172, action:"Do not pay or update payment details from the message path; verify through an official billing route."},
    "Money movement scam": {id:"LANE-MONEY-020", label:"Money transfer, deposit, or payment-rail request", priority:214, action:"Do not accept, send, release, reverse, or verify money from the message path; open the official banking/payment app directly."},
    "Gift/prize scam": {id:"LANE-REWARD-021", label:"Gift card, prize, or reward-claim request", priority:213, action:"Do not buy, send, upload, redeem, or verify gift cards/rewards from the message path; verify through the official rewards account directly."},
    "Subscription renewal scam": {id:"LANE-SUBSCRIPTION-022", label:"Subscription, renewal, or billing-update request", priority:212, action:"Do not update payment details, renew, reactivate, or cancel from the message path; open the official service account directly."},
    "Delivery scam": {id:"LANE-DELIVERY-005", label:"Delivery, parcel, courier, or customs request", priority:211, action:"Check tracking only through the official carrier site or app; do not pay delivery fees or correct addresses from the message path."},
    "Parking/toll/transit scam": {id:"LANE-MOBILITY-019", label:"Parking, toll, transit, or vehicle-payment request", priority:230, action:"Do not pay a parking, toll, ticket, or transit fee from a random QR/link; verify through the official meter, city, toll, or transit app."},
    "Government/legal scam": {id:"LANE-GOV-006", label:"Government, tax, benefit, identity, or legal pressure", priority:216, action:"Do not pay, claim benefits, upload ID, or verify government accounts from a random link; use the official agency site typed manually or a known phone number."},
    "Fake security alert": {id:"LANE-SECURITY-007", label:"Security or tech-support alert", priority:134, action:"Do not call numbers or install tools from the alert; use the official support path."},
    "Job scam": {id:"LANE-JOB-008", label:"Job, recruitment, or work-from-home request", priority:217, action:"Verify the recruiter and company through official channels before sharing identity, banking data, fees, gift cards, or accepting equipment/reshipping tasks."},
    "AI emergency scam": {id:"LANE-AI-023", label:"AI voice, new-number, or family-emergency impersonation", priority:225, action:"Verify the person by calling a known number or another trusted family channel before sending money, codes, gift cards, or crypto."},
    "Social DM scam": {id:"LANE-DM-024", label:"Social media DM, influencer, giveaway, or off-platform lure", priority:224, action:"Do not move to private chat, connect accounts, pay, or claim rewards until the profile and destination are verified through the official app."},
    "Marketplace scam": {id:"LANE-MARKET-025", label:"Marketplace buyer-seller, courier, overpayment, or release-funds request", priority:223, action:"Keep payment inside the trusted marketplace and avoid courier, overpayment, refund-extra, or payment-pending links."},
    "Student scam": {id:"LANE-STUDENT-026", label:"Student, school, scholarship, grant, or campus portal request", priority:222, action:"Verify scholarships, grants, tuition refunds, campus jobs, and school logins through the official school portal typed manually."},
    "Fake recovery scam": {id:"LANE-RECOVERY-SCAM-027", label:"Fake scam-report, refund-investigation, or stolen-funds recovery request", priority:226, action:"Do not pay recovery fees or enter bank/wallet details into recovery portals; report through official channels typed manually."},
    "Crypto/investment scam": {id:"LANE-CRYPTO-009", label:"Crypto or investment offer", priority:134, action:"Do not connect wallets, share seed phrases, or pay release/recovery fees."},
    "Trust/social-engineering scam": {id:"LANE-SOCIAL-010", label:"Trust-building or social-engineering message", priority:122, action:"Slow down and verify the person/story through a separate channel before sending money or private info."},
    "Callback scam": {id:"LANE-CALLBACK-011", label:"Callback or phone-pressure request", priority:182, action:"Do not call the supplied number; use a trusted number from the official source."},
    "Urgency / pressure tactic": {id:"LANE-PRESSURE-012", label:"Urgency or fear-pressure tactic", priority:180, action:"Pause before acting; pressure language is a warning to verify independently."},
    "Authority impersonation": {id:"LANE-AUTH-013", label:"Authority impersonation voice", priority:174, action:"Verify any official-sounding claim through a known channel, not the original message."},
    "MFA / OTP code theft": {id:"LANE-OTP-014", label:"Verification code theft", priority:178, action:"Never share or approve one-time codes unless you initiated the login through a trusted route."},
    "Account recovery takeover": {id:"LANE-RECOVERY-015", label:"Account recovery takeover", priority:176, action:"Do not use unexpected recovery/reset links; go directly to the official account page."},
    "Copied HTML trap": {id:"LANE-HTML-016", label:"Copied email or hidden HTML trap", priority:120, action:"Do not trust the visible button/link text; verify the actual destination."},
    "Redirect/wrapper risk": {id:"LANE-REDIRECT-017", label:"Redirect or link-wrapper pattern", priority:112, action:"Treat hidden destinations as review-needed until the final root is known."},
    "General structure": {id:"LANE-GENERAL-018", label:"General local warning pattern", priority:80, action:"Review the visible root, purpose, and sender before acting."}
  };

  function getThreatLane(family){
    return THREAT_LANE_INDEX[family] || THREAT_LANE_INDEX["General structure"];
  }

  function classifyEvidenceWeight(signal){
    const title = String((signal && signal.title) || "").toLowerCase();
    const detail = String((signal && signal.detail) || "").toLowerCase();
    const text = title + " " + detail;
    if (/script|local scheme|unreadable|broken punycode|username-in-link|authority boundary|double-extension|risky file|private or local-network|ip address|unicode|punycode|trusted domain embedded|trusted root stuffed|lookalike institution|short institution alias|near-miss institution|parser control|html form submits|meta refresh redirect|javascript redirect snippet|hidden html link|credential-harvest|government \/ tax \/ legal threat|fake security alert \/ tech support|crypto \/ investment scam|romance \/ trust-building social engineering|job \/ employment scam|ai \/ family emergency impersonation|social media dm \/ influencer scam|marketplace buyer-seller scam|student \/ school portal scam|fake recovery \/ report portal scam|payment \/ invoice scam|delivery \/ customs scam|money movement \/ payment rail scam|gift card \/ prize \/ reward claim scam|parking \/ toll \/ transit scam|attachment \/ file trap|callback scam intent|urgency \/ pressure tactic|mfa \/ otp code theft|account recovery \/ password reset takeover/.test(text)) return "critical";
    if (/brand outside verified root|cross-root redirect|trusted-brand redirect mismatch|phishing-kit|random-looking root|embedded redirect target|encoded separator|double-encoded|non-web scheme|pressure wording|hidden or invisible html content/.test(text)) return "strong";
    if (/no clear https|credential-like|dense query|shortener|heavy subdomain|extra subdomain|heavy hyphen|brand plus hyphen|encoded characters|higher-risk tld|sensitive workflow|lookalike security word|very long url|malformed domain punctuation|unusual network port|protocol-relative|embedded link present|trusted share wrapper|final destination not visible offline|multiple html links|button\/image link/.test(text)) return "medium";
    return "weak";
  }

  function buildEvidenceProfile(signals){
    const profile = {critical:[], strong:[], medium:[], weak:[], positive:[]};
    (signals || []).forEach(signal => {
      const bucket = signal.weight < 0 ? "positive" : classifyEvidenceWeight(signal);
      profile[bucket].push(signal);
      signal.weightClass = bucket;
    });
    return profile;
  }

  function evidenceProfileSummary(profile){
    return profile.critical.length + " critical · " + profile.strong.length + " strong · " + profile.medium.length + " medium · " + profile.weak.length + " weak · " + profile.positive.length + " trust-relief";
  }

  function highestEvidenceClass(profile){
    if (profile.critical.length) return "Critical";
    if (profile.strong.length) return "Strong";
    if (profile.medium.length) return "Medium";
    if (profile.weak.length) return "Weak";
    if (profile.positive.length) return "Trust relief only";
    return "None";
  }

  function describeIgnoredSignals(profile){
    const ignored = [];
    profile.weak.slice(0,3).forEach(s => ignored.push("Low-weight: " + s.title));
    profile.positive.slice(0,3).forEach(s => ignored.push("Trust relief: " + s.title));
    return ignored.length ? ignored : ["No low-weight or ignored signals dominated the decision."];
  }


  function isCredentialPressurePayload(ctx){
    const target = ctx && ctx.target;
    if (!target || target.type !== "payload") return false;
    const raw = String(target.sourceRaw || target.raw || target.href || "").toLowerCase();
    const hasCredential = /\b(password|passcode|otp|one[-\s]?time|2fa|mfa|pin|verification[-\s]?code|security[-\s]?code|login[-\s]?code|code|token|credential)\b/.test(raw);
    const hasAccountPressure = /\b(account|login|sign[-\s]?in|security)\b/.test(raw) && /\b(suspend(?:ed)?|locked|blocked|verify|confirm|validate|urgent|now|required|final|expire(?:d|s)?)\b/.test(raw);
    const hasMoneyCore = /\b(payment|deposit|transfer|bank|card|invoice|billing|refund|rebate|transaction|funds|money|interac|e[-\s]?transfer|zelle|venmo|paypal|wire)\b/.test(raw);
    return hasCredential && hasAccountPressure && !hasMoneyCore;
  }

  function selectDominantSignal(ctx, profile){
    const signals = (ctx && ctx.signals) || [];
    if (!signals.length) return null;
    const severityBoost = {high:80, medium:35, low:8};
    const classBoost = {critical:120, strong:70, medium:30, weak:5, positive:-20};
    const familyBoost = Object.keys(THREAT_LANE_INDEX).reduce((acc, family) => {
      acc[family] = THREAT_LANE_INDEX[family].priority;
      return acc;
    }, {});
    let best = null;
    const credentialPressurePayload = isCredentialPressurePayload(ctx);
    const rawContext = normalizeUnicodeConfusables((ctx && ctx.target && (ctx.target.sourceRaw || ctx.target.raw || ctx.target.href)) || "");
    const romanceContext = /\b(romance|dating|love|relationship|sweetheart|private photo|move off platform|stranded|emergency money)\b/.test(rawContext);
    const callbackContext = /\b(call this number|call back|callback|phone us|contact support|support number)\b/.test(rawContext);
    const recoveryContext = /\b(password reset|reset password|account recovery|recovery link|unlock account|account unlock|new device|email change|session reset)\b/.test(rawContext);
    const fileInvoiceContext = /\b(invoice|statement|document|attachment|shared file|macro|enable content|download)\b/.test(rawContext) && /\b(file|attachment|document|macro|download|enable content)\b/.test(rawContext);
    const explicitOtpContext = /\b(otp|one[-\s]?time code|verification code|security code|2fa|mfa|authenticator|push approval)\b/.test(rawContext);
    signals.forEach((signal, index) => {
      const family = classifySignalFamily(signal);
      signal.family = family;
      const weightMagnitude = Math.max(0, Number(signal.weight || 0));
      let v3195Boost = 0;
      if (credentialPressurePayload && /^(Credential theft|MFA \/ OTP code theft|Account recovery takeover|Urgency \/ pressure tactic)$/.test(family)) v3195Boost += 180;
      if (credentialPressurePayload && /^(Money movement scam|Payment scam|Subscription renewal scam|Fake security alert)$/.test(family)) v3195Boost -= 220;

      let v338ContextBoost = 0;
      if (romanceContext && family === "Trust/social-engineering scam") v338ContextBoost += 280;
      if (romanceContext && /^(Parking\/toll\/transit scam|Government\/legal scam)$/.test(family)) v338ContextBoost -= 240;
      if (callbackContext && family === "Callback scam") v338ContextBoost += 420;
      if (callbackContext && explicitOtpContext && family === "MFA / OTP code theft") v338ContextBoost += 360;
      if (callbackContext && /^(Government\/legal scam|Subscription renewal scam)$/.test(family) && !/\b(tax|court|warrant|government|cra|irs|benefit|renewal|subscription|billing)\b/.test(rawContext)) v338ContextBoost -= 320;
      if (callbackContext && explicitOtpContext && family === "Fake security alert") v338ContextBoost -= 120;
      if (recoveryContext && family === "Account recovery takeover") v338ContextBoost += 270;
      if (recoveryContext && family === "MFA / OTP code theft" && !explicitOtpContext) v338ContextBoost -= 230;
      if (fileInvoiceContext && family === "File/download trap") v338ContextBoost += 260;
      if (fileInvoiceContext && family === "Subscription renewal scam") v338ContextBoost -= 210;

      const score = (classBoost[signal.weightClass] || 0) + (severityBoost[signal.severity] || 0) + (familyBoost[family] || 0) + weightMagnitude + v3195Boost + v338ContextBoost - (index * 0.01);
      signal.dominanceScore = Math.round(score * 100) / 100;
      if (!best || signal.dominanceScore > best.dominanceScore) best = signal;
    });
    return best;
  }

  function summarizeDominantThreat(dominant, profile){
    if (!dominant) return "No dominant threat selected; the report is based on light local evidence.";
    const family = dominant.family || classifySignalFamily(dominant);
    const lane = getThreatLane(family);
    const supporting = (profile.critical || []).concat(profile.strong || []).filter(s => s !== dominant).slice(0,2).map(s => s.title);
    return lane.id + " / " + lane.label + " selected as the main lane from " + (dominant.weightClass || "unclassified") + " evidence" + (supporting.length ? "; supporting: " + supporting.join("; ") : "; no stronger supporting lane outranked it");
  }

  function makeScoreBand(score){
    if (score >= 80) return {label:"Critical stop zone", action:"Block", note:"The score is in the highest local-risk band because strong evidence needs protective action."};
    if (score >= 60) return {label:"High-risk stop zone", action:"Block", note:"The score reached the stop band from high-severity or strong evidence."};
    if (score >= 35) return {label:"Verification zone", action:"Verify", note:"The score is not clean enough for sensitive action without a second check."};
    if (score >= 20) return {label:"Caution zone", action:"Verify", note:"The score is lightly raised because one or more caution clues need context."};
    return {label:"Low local-risk zone", action:"Allow with caution", note:"The score stayed low because no major offline warning pattern dominated the scan."};
  }

  function makeCalmTriage(risk, score, target, dominant, profile, high, medium, low){
    const band = makeScoreBand(score);
    const family = dominant ? (dominant.family || classifySignalFamily(dominant)) : "No dominant scam lane";
    const evidenceCount = (profile.critical.length + profile.strong.length + profile.medium.length + profile.weak.length);
    let action = band.action;
    if (risk === "High Risk") action = "Block / stop";
    else if (risk === "Needs Review") action = "Verify first";
    else action = "Allow with normal caution";
    const rationale = "Score band: " + band.label + ". Main lane: " + family + ". Evidence mix: " + evidenceProfileSummary(profile) + ".";
    const user = risk === "High Risk"
      ? "Stop first, then verify through a separate trusted route."
      : (risk === "Needs Review" ? "Do not act from the original message until the source and destination are confirmed." : "No major local warning signs dominated, but still use official paths for sensitive actions.");
    return {band:band.label, action, rationale, user, note:band.note, evidenceCount};
  }


  function lanePlainName(family){
    return getThreatLane(family).label;
  }

  function makeWhatToDoNextGuidance(risk, target, dominant, calmTriage, evidenceProfile){
    const family = dominant ? (dominant.family || classifySignalFamily(dominant)) : "No dominant scam lane";
    const lane = lanePlainName(family);
    const root = (target && target.root) ? target.root : "the shown destination";
    const origin = target && target.type === "payload" ? "QR/text payload" : "link or domain";
    const strong = (evidenceProfile && (evidenceProfile.critical.length || evidenceProfile.strong.length)) || 0;
    if (risk === "High Risk") {
      return {
        actionTitle:"Stop — verify elsewhere",
        actionText:"Do not click further, sign in, call the number, download a file, or enter payment/details from this " + origin + ". Open the official app/site yourself or contact the organization through a trusted route.",
        whyTitle:"Main concern: " + lane,
        whyText:"Proxuma selected this lane because the strongest local evidence points to " + lane + ". The visible root was " + root + ", but the safest move is to verify outside the original message.",
        safetyTitle:"Safe next move",
        safetyText:"Close the message path, preserve the original if needed, and only continue from a bookmark, saved app, official phone number, or known website typed manually.",
        steps:["Stop interacting with the original message or QR path.", "Do not enter passwords, codes, banking info, personal ID, or download files.", "Verify through an official app/bookmark/known number, not through the scanned link."]
      };
    }
    if (risk === "Needs Review") {
      return {
        actionTitle:"Pause — verify first",
        actionText:"Treat this as unfinished until you confirm the sender, root domain, and reason for the request. Use a separate trusted route before taking sensitive action.",
        whyTitle:"Review focus: " + lane,
        whyText:"The scan found enough local evidence to require caution, but not enough to call it a hard stop. Check whether " + root + " is the exact destination you expected.",
        safetyTitle:"Verification path",
        safetyText:"Open the official app or type the known website manually. If this came by email, SMS, chat, or QR code, do not trust the message alone.",
        steps:["Check the real root domain and sender context.", "Avoid sensitive actions until the request is confirmed elsewhere.", "Use official routes instead of replying, calling, or clicking from the message."]
      };
    }
    return {
      actionTitle:"Proceed with normal caution",
      actionText:"No major offline warning lane dominated this scan. Continue only if the destination and reason match what you expected.",
      whyTitle:"Low local-risk result",
      whyText: strong ? "Some low-weight context was recorded, but safe/trusted context kept the verdict calm." : "The local scan did not find a dominant scam-intent pattern for this target.",
      safetyTitle:"Normal safety habit",
      safetyText:"For logins, payments, files, or private data, prefer bookmarks, official apps, or a typed address even when the local score is low.",
      steps:["Confirm the page matches your intended destination.", "Use official routes for sensitive actions.", "Stay cautious if the link arrived unexpectedly."]
    };
  }



  function makeReportConsistencyPack(risk, target, dominant, guidance, evidenceProfile){
    const family = dominant ? (dominant.family || classifySignalFamily(dominant)) : "No dominant scam lane";
    const lane = getThreatLane(family);
    const root = (target && target.root) ? target.root : "the resolved destination";
    const raw = (target && target.raw) ? target.raw : "the submitted target";
    const origin = target && target.type === "payload" ? "QR/text payload" : "link or domain";
    const strength = evidenceProfile ? evidenceProfileSummary(evidenceProfile) : "no signal mix available";
    const eventLine = dominant
      ? "Proxuma IT matched the " + lane.label + " lane from the strongest local evidence in this " + origin + "."
      : "Proxuma IT did not find a dominant scam lane in this " + origin + ".";
    const nextMove = (guidance && guidance.actionText) || "Use a trusted route before taking sensitive action.";
    const safetyHabit = (guidance && guidance.safetyText) || "Use official apps, saved bookmarks, or typed addresses for sensitive actions.";
    const why = (guidance && guidance.whyText) || "The result is based on local structure, wording, destination, and behavior signals.";
    const reportName = lane.reportName || lane.label;
    const laneId = lane.id || "LANE-NONE-000";
    return {
      laneId,
      laneLabel: lane.label,
      laneReportName: reportName,
      laneAction: lane.action || (guidance && guidance.actionTitle) || "Use caution",
      whatHappened: eventLine + " Resolved root: " + root + ".",
      whyItMatters: why,
      whatToDoNext: nextMove,
      safetyHabit,
      evidenceMix: strength,
      reportChecklist: [
        "What happened: " + eventLine,
        "Why it matters: " + why,
        "What to do next: " + nextMove,
        "Safety habit: " + safetyHabit,
        "Threat lane: " + laneId + " / " + reportName
      ],
      analystLine: laneId + " / " + reportName + " · root " + root + " · evidence mix " + strength + " · raw " + raw
    };
  }

  function classifySafeTrustedContextRelief(target, signals, messageContext){
    const result = {active:false, level:"none", safetyBoost:0, title:"", detail:""};
    if (!target || target.type !== "url") return result;
    const knownRoot = isKnownRoot(target) || !!matchingTrustedFamily(target.root);
    if (!knownRoot) return result;
    const titles = (signals || []).map(s => String((s.title || "") + " " + (s.detail || "")).toLowerCase()).join(" | ");
    const hardStop = /username-in-link|authority boundary|double-extension|executable download|risky file|unicode|punycode|ip address|private or local-network|parser control|html form submits|meta refresh|javascript redirect|hidden html link|brand \/ destination mismatch|message brand \/ destination mismatch|visible label \/ real destination mismatch|trusted root stuffed|trusted domain embedded|lookalike institution|near-miss institution|short institution alias|cross-root redirect|trusted-root redirect to sensitive external destination/.test(titles);
    if (hardStop) return result;
    const mediumCount = (signals || []).filter(s => s.severity === "medium").length;
    const highCount = (signals || []).filter(s => s.severity === "high").length;
    const pressureCount = ((messageContext && messageContext.pressure) || []).length;
    const candidateCount = ((messageContext && messageContext.candidates) || []).length;
    const firstPartySignals = /known trusted root|credential workflow on known root|same-root redirect|first-party redirect|credential parameter on known root|encoded first-party|encoded same-root/.test(titles);
    const normalWorkflow = /login|signin|account|payment|billing|invoice|refund|delivery|tracking|support|security|verify|verification|tax|benefit|document|file|statement/.test(String((target.raw || "") + " " + (target.path || "")).toLowerCase());
    const mismatched = ((messageContext && messageContext.mismatchedBrands) || []).length > 0;
    if (mismatched) return result;
    if (highCount === 0 && firstPartySignals && pressureCount <= 2 && candidateCount <= 1) {
      result.active = true;
      result.level = mediumCount <= 1 ? "strong" : "moderate";
      result.safetyBoost = mediumCount <= 1 ? 10 : 6;
      result.title = "Safe/trusted context relief";
      result.detail = "v2.90 recognized a known local root with first-party or normal workflow context and no hard-stop deception. This lowers false-positive pressure without declaring the page verified online.";
      return result;
    }
    if (highCount === 0 && normalWorkflow && pressureCount <= 1 && candidateCount <= 1 && mediumCount <= 2) {
      result.active = true;
      result.level = "light";
      result.safetyBoost = 4;
      result.title = "Normal trusted workflow relief";
      result.detail = "v2.90 found ordinary login, payment, delivery, support, document, or account wording on a known local root. The wording is recorded as context rather than treated as scam intent by itself.";
      return result;
    }
    return result;
  }

  function calibrateRiskScore(rawRiskScore, ctx, high, medium, low){
    let score = rawRiskScore;
    const target = ctx.target || {};
    const knownRoot = isKnownRoot(target);
    const severeTitles = (ctx.signals || []).filter(s => s.severity === "high").map(s => s.title).join(" ").toLowerCase();
    const hardStop = /username-in-link|double-extension|risky file|unicode|punycode|ip address|script|local scheme|unreadable|brand outside verified root|near-miss|lookalike|trusted domain embedded|trusted root stuffed/.test(severeTitles);

    const payloadTitles = (ctx.signals || []).map(s => s.title).join(" ").toLowerCase();
    const simplePayload = /numeric qr payload|short code \/ reference payload/.test(payloadTitles);
    if (target.type === "payload" && simplePayload && high === 0 && medium === 0) score = Math.min(score, 8);
    else if (target.type === "payload" && high === 0 && medium <= 1) score = Math.max(score, 22);

    if (knownRoot && high === 0 && !hardStop) {
      if (medium === 0) score = Math.min(score, 10);
      else if (medium === 1) score = Math.min(score, 18);
      else score = Math.min(score, 38);
    }

    if (!knownRoot && high === 0 && medium === 1 && score > 32) score = 32;
    if (!knownRoot && high === 0 && medium === 0 && low === 0 && score < 8) score = 8;
    return Math.max(0, Math.min(100, Math.round(score)));
  }

  function classifyQrPayload(raw){
    const value = String(raw || "").trim();
    const lower = normalizeUnicodeConfusables(value);
    const decoded = normalizeUnicodeConfusables(safeDecodeForInspection(value));
    const urls = (value.match(/https?:\/\/[^\s]+/ig) || []).concat(decoded.match(/https?:\/\/[^\s]+/ig) || []);
    const prefix = qrStructuredPrefixes.find(p => lower.startsWith(p));
    const numeric = /^\d{6,}$/.test(value);
    const shortCode = /^[a-z0-9_-]{4,32}$/i.test(value);
    const denseEncoded = /%[0-9a-f]{2}/i.test(value) && value.length > 40;
    const workflowHits = Array.from(highValueWorkflowWords).filter(word => lower.includes(word) || decoded.includes(word));
    if (prefix) return {kind:"Structured QR payload", safety:78, severity:"low", detail:"This looks like a structured QR format such as Wi-Fi, contact, phone, SMS, mail, geo, or authenticator setup data. It is not judged like a normal web link.", prefix, workflowHits};
    if (/^(ftp|sftp|chrome-extension|blob|about|content):/i.test(value)) return {kind:"Non-web scheme payload", safety:54, severity:"medium", detail:"This begins with a non-HTTP scheme. Proxuma kept it out of normal web trust scoring because browsers and apps may handle it differently than a normal website.", workflowHits};
    if (/^[^\s/]+@[^\s/]+\.[a-z]{2,}/i.test(value) || /@[^\s/]+\.[a-z]{2,}/i.test(value)) return {kind:"Authority/userinfo-like payload", safety:42, severity:"high", detail:"This text resembles a URL authority trick using an @ sign. The text before @ may be decoration while the destination after @ controls where the browser goes.", workflowHits};
    if (urls.length) return {kind:"Embedded URL inside QR/text", safety:58, severity:"medium", detail:"This text payload contains a URL inside it. Open or scan the embedded link only after checking the real root domain.", urls:Array.from(new Set(urls)).slice(0,2), workflowHits};
    if (numeric) return {kind:"Numeric QR payload", safety:90, severity:"low", detail:"This looks like an ID, product code, ticket number, or internal reference rather than a website.", workflowHits};
    if (denseEncoded) return {kind:"Dense encoded QR/text payload", safety:62, severity:"medium", detail:"This payload contains encoded characters and enough length to hide meaning. Review the source before acting on it.", workflowHits};
    if (workflowHits.length >= 3) return {kind:"Sensitive non-URL payload", safety:60, severity:"medium", detail:"This non-URL payload contains several login, account, payment, or security words. Context matters before trusting it.", workflowHits};
    if (shortCode) return {kind:"Short code / reference payload", safety:86, severity:"low", detail:"This looks like a compact code or reference value rather than a destination link.", workflowHits};
    return {kind:"Non-URL QR/text payload", safety:value.length > 120 ? 64 : 76, severity:value.length > 120 ? "medium" : "low", detail:"This was not forced into a URL verdict. Context matters before acting on it.", workflowHits};
  }

  function matchingTrustedFamily(root){
    return brandFamilies.find(f => f.roots.some(r => root === r || root.endsWith("." + r))) || null;
  }

  function analyze(raw){
    const target = normalizeTarget(raw);
    const signals = [];
    const technical = [];
    const trust = [];
    const timeline = [];
    let score = 92;

    timeline.push("Input received and classified locally. No external lookup was used.");
    technical.push("v3.19 QR honesty layer: camera QR scanning is user-triggered and browser-dependent. Native BarcodeDetector is used when available; other supported browsers use the packaged local jsQR decoder, with manual QR text paste as an additional fallback. Decoded or pasted payloads still feed into the offline engine; no API calling is active.");
    technical.push("Next path: QR scanner first, then offline QR hardening, then explicit user-approved Online Intel/API bridge.");

    if (target.type === "empty") return emptyReport();

    if (target.type === "dangerous-scheme") {
      score = 42;
      addSignal(signals,"high","Script or local scheme","The payload begins with a scheme such as javascript:, data:, file:, or vbscript:. These are not normal web destinations and can carry script/content instead of a safe website.",32);
      technical.push("Dangerous/non-web scheme detected: " + target.scheme + ":");
      trust.push("Script/local scheme lane used instead of normal website trust scoring.");
      timeline.push("Proxuma blocked normal trust relief because the input uses a script/local content scheme.");
      return finalize({target, score, signals, technical, trust, timeline});
    }

    if (target.scheme === "unreadable" && /^https?:\/\//i.test(target.raw)) {
      score = 44;
      addSignal(signals,"high","Unreadable URL structure","The input looks like a web URL but the browser parser could not read it cleanly. Broken punycode, malformed hostnames, or illegal characters should be treated cautiously.",30);
      if (/xn--/i.test(target.raw)) addSignal(signals,"high","Broken punycode lookalike attempt","The unreadable URL includes punycode-style text. Punycode can be used in lookalike-domain attacks, and malformed punycode should not be trusted.",28);
      technical.push("URL-like input failed parsing and was not treated as a trusted normal URL.");
      trust.push("No trusted-root relief applied because the URL was unreadable.");
      timeline.push("URL parser failed; Proxuma escalated instead of treating it as harmless text.");
      return finalize({target, score, signals, technical, trust, timeline});
    }

    if (target.type === "payload") {
      const payload = classifyQrPayload(target.raw);
      score = payload.safety;
      addSignal(signals, payload.severity, payload.kind, payload.detail, payload.severity === "medium" ? 14 : 4);
      const recoveredEncodedUrls = extractCandidateUrls(target.sourceRaw || target.raw).filter(url => !String(target.raw || "").includes(url));
      if (recoveredEncodedUrls.length) {
        score = Math.min(score, 48);
        addSignal(signals, "high", "Percent-encoded URL recovered", "The message contained a URL hidden behind percent encoding. Proxuma decoded the candidate locally and deep-scanned the recovered destination.", 26);
        technical.push("v3.38 encoded-message recovery: recovered " + recoveredEncodedUrls[0] + " from percent-encoded text.");
        timeline.push("Proxuma decoded a URL-shaped percent-encoded message before classification.");
        payload.urls = Array.from(new Set((payload.urls || []).concat(recoveredEncodedUrls))).slice(0,3);
      }
      const rawPayloadText = String(target.sourceRaw || target.raw || "");
      const normalizedPayloadText = normalizeUnicodeConfusables(rawPayloadText);
      if (normalizedPayloadText !== rawPayloadText.toLowerCase() && /\b(verify|account|login|password|payment|urgent|security|code|reset|support)\b/.test(normalizedPayloadText)) {
        score = Math.min(score, 46);
        addSignal(signals, "high", "Unicode lookalike wording", "The message uses non-Latin lookalike letters inside sensitive account or security language. This can make scam wording appear visually normal while evading simple text checks.", 24);
        technical.push("v3.38 Unicode confusable normalization changed sensitive message text before classification.");
      }
      const payloadEndingSpoof = inspectDomainEndingSpoof(target);
      if (payloadEndingSpoof.active) {
        score = Math.min(score, payloadEndingSpoof.kind === "comma-domain" ? 40 : 36);
        addSignal(signals, payloadEndingSpoof.severity, payloadEndingSpoof.title, payloadEndingSpoof.detail, payloadEndingSpoof.weight);
        technical.push("v3.24.1 domain-ending spoof check: " + payloadEndingSpoof.kind + " detected in payload lane.");
        timeline.push("v3.24.1 checked whether the payload used comma-domain punctuation or a .com-style ending imitation.");
      }
      if (payload.urls && payload.urls.length) {
        addSignal(signals, "medium", "Embedded link present", "Embedded URL sample: " + payload.urls[0] + ". Proxuma v2.60 deep-scans the embedded destination instead of stopping at payload classification.", 12);
        const embeddedDeepScan = analyze(payload.urls[0]);
        technical.push("v2.60 embedded URL deep scan: " + embeddedDeepScan.risk + " / " + embeddedDeepScan.root + " / " + embeddedDeepScan.primaryTrigger + ".");
        timeline.push("v2.60 deep-scanned the first embedded URL found inside the QR/text payload.");
        if (/download|executable|installer|archive|risky file|double-extension/i.test(JSON.stringify(embeddedDeepScan))) {
          technical.push("v2.61 embedded download-trap intelligence: executable/download evidence found inside embedded URL report.");
        }
        if (embeddedDeepScan.risk === "High Risk") {
          score = Math.min(score, 34);
          addSignal(signals, "high", "Embedded URL deep-scan high risk", "The URL inside this QR/text payload produced a high-risk local verdict: " + embeddedDeepScan.primaryTrigger + ". Treat the payload as unsafe until verified another way.", 28);
        } else if (embeddedDeepScan.risk === "Needs Review") {
          score = Math.min(score, 54);
          addSignal(signals, "medium", "Embedded URL needs review", "The URL inside this QR/text payload needs review: " + embeddedDeepScan.primaryTrigger + ". Verify the destination root before opening it.", 14);
        } else if (embeddedDeepScan.risk === "Low Risk") {
          score = Math.max(score, 78);
          trust.push("Embedded URL deep scan found low local risk for " + embeddedDeepScan.root + ", but QR source context still matters.");
          addSignal(signals, "low", "Embedded URL low local risk", "The embedded URL resolved to a low-risk local structure: " + embeddedDeepScan.root + ". This helps, but it does not verify the QR source or intent.", -4);
        }
      }
      const payloadMessageContext = analyzeMessageContext(target.sourceRaw || target.raw, (target.embeddedCandidates && target.embeddedCandidates.length ? target.embeddedCandidates : extractCandidateUrls(target.sourceRaw || target.raw).concat(payload.urls || [])), "");
      if (payloadMessageContext.envelope !== "Direct target") technical.push("Message intelligence envelope: " + payloadMessageContext.envelope + ".");
      const payloadHtmlArtifacts = inspectHtmlEmailArtifacts(target.sourceRaw || target.raw);
      if (payloadHtmlArtifacts.isHtml) {
        technical.push("v2.58 HTML email intelligence: copied HTML/snippet patterns detected in payload mode.");
        timeline.push("v2.58 inspected copied email/page HTML while preserving payload classification.");
        if (payloadHtmlArtifacts.anchors.length > 1) addSignal(signals,"medium","Multiple HTML links in copied content","The pasted HTML/email block contains multiple anchors. Review every destination, not only the first visible button or link.",12);
        if (payloadHtmlArtifacts.buttonLike || payloadHtmlArtifacts.imageLinks) addSignal(signals,"medium","Button/image link in copied email","The copied content uses a button-like or image-based link. Scam emails often hide the true URL behind friendly graphics.",10);
        if (payloadHtmlArtifacts.forms.length) addSignal(signals,"high","HTML form submits to a web destination","The copied content includes a form action that can collect credentials or payment details.",22);
        if (payloadHtmlArtifacts.metaRefresh.length) addSignal(signals,"high","HTML meta refresh redirect","The copied content includes a meta refresh redirect. This can move a browser to another destination without a normal click.",22);
        if (payloadHtmlArtifacts.scriptRedirects.length) addSignal(signals,"high","JavaScript redirect snippet","The copied content includes script-style redirection. Treat copied redirect code as unsafe unless verified by a trusted source.",22);
        if (payloadHtmlArtifacts.hidden.length) addSignal(signals,"medium","Hidden or invisible HTML content","The copied content contains hidden-display styling (" + Array.from(new Set(payloadHtmlArtifacts.hidden)).join(", ") + ").",14);
        if (payloadHtmlArtifacts.hidden.length && payloadHtmlArtifacts.anchors.length) addSignal(signals,"high","Hidden HTML link present","The copied HTML contains hidden styling plus at least one link. Hidden links can conceal a destination from the person reading the message.",22);
      }
      if (payloadMessageContext.pressure.length >= 2) addSignal(signals, "medium", "Payload pressure tactics", "The QR/message payload uses pressure wording: " + payloadMessageContext.pressure.slice(0,6).join(", ") + ".", 12);
      if (payloadMessageContext.candidates.length > 1) addSignal(signals, "medium", "Multiple embedded links", "The payload contains " + payloadMessageContext.candidates.length + " link-like targets. Review all destinations instead of trusting the first one visible.", 14);
      const structuredSchemeWithLink = ["mailto","sms","smsto","wifi","matmsg"].includes(String(target.scheme || "").toLowerCase()) && payloadMessageContext.roots.length > 0;
      const structuredBrandMismatch = structuredSchemeWithLink && payloadMessageContext.visibleBrandHints.length && payloadMessageContext.roots.some(item => !matchingTrustedFamily(item.root));
      if (payloadMessageContext.visibleBrandHints.length && payloadMessageContext.roots.some(item => !matchingTrustedFamily(item.root)) && (payloadMessageContext.pressure.length >= 2 || structuredBrandMismatch)) addSignal(signals, "high", structuredBrandMismatch ? "Structured payload brand / destination mismatch" : "Message brand / destination mismatch", "The payload names a trusted brand or service and also contains a link outside that official family. Treat the message as suspicious until verified.", 22);
      if (structuredSchemeWithLink && payloadMessageContext.pressure.length && payloadMessageContext.roots.some(item => !matchingTrustedFamily(item.root))) addSignal(signals, "high", "Structured message carries sensitive external link", "A mail/SMS/Wi-Fi-style payload contains pressure wording plus a web destination outside a known trusted family. Do not follow it without verifying through the official app or site.", 20);
      if (payloadMessageContext.highRiskCandidates.length) {
        const sample = payloadMessageContext.highRiskCandidates[0];
        addSignal(signals, "high", "Risky link hidden among multiple links", "At least one embedded destination looks risky (sample root: " + sample.root + "). Review every link in the message, not only the first visible one.", 22);
      }
      const payloadCredentialWords = Array.from(credentialIntentWords).filter(word => String(target.sourceRaw || target.raw).toLowerCase().includes(word));
      const payloadCollectionWords = Array.from(credentialCollectionWords).filter(word => String(target.sourceRaw || target.raw).toLowerCase().includes(word));
      if ((payloadCredentialWords.length >= 2 && (payloadCollectionWords.length || payloadMessageContext.pressure.length >= 2)) || payloadMessageContext.mismatchedBrands.length) {
        addSignal(signals, "high", "Payload credential-harvest intent", "The QR/message payload combines credential or account-access wording with pressure, collection language, or brand/destination mismatch. Do not enter passwords, PINs, OTP codes, or payment details from this payload.", 20);
        technical.push("v2.66 credential-harvest intent: payload/message wording escalated for credential collection risk.");
        timeline.push("v2.66 checked payload wording for credential-harvest intent before final advice.");
      }
      const payloadCallbackIntent = inspectCallbackScamIntent(target, payloadMessageContext);
      if (payloadCallbackIntent.active) {
        score -= payloadCallbackIntent.weight;
        const phoneSample = payloadCallbackIntent.phones.length ? " Phone clue: " + payloadCallbackIntent.phones[0] + "." : "";
        addSignal(signals, payloadCallbackIntent.severity, "Callback scam intent pattern", "The QR/message payload pushes the user toward phone/support contact while also carrying pressure, account, payment, refund, delivery, tax, or security context." + phoneSample + " Verify through an official app, typed website, or known phone number instead of the message.", payloadCallbackIntent.weight);
        technical.push("v2.78 callback scam intent: phone-first social-engineering pattern detected in payload/message lane.");
        timeline.push("v2.78 checked whether the payload was trying to move the user from a link/QR into a phone-support scam flow.");
      }
      const payloadAttachmentIntent = inspectAttachmentFileTrapIntent(target, payloadMessageContext);
      if (payloadAttachmentIntent.active) {
        score -= payloadAttachmentIntent.weight;
        const sample = payloadAttachmentIntent.macroWords[0] || payloadAttachmentIntent.executableHits[0] || payloadAttachmentIntent.archiveHits[0] || payloadAttachmentIntent.cloudBrands[0] || payloadAttachmentIntent.fileIntent[0] || "file-access wording";
        addSignal(signals, payloadAttachmentIntent.severity, "Attachment / file trap intent", "The QR/message payload uses document, invoice, shared-file, cloud-file, macro, or download-style language that can push the user into opening a risky file. Evidence: " + sample + ". Verify through the official account or sender before opening anything.", payloadAttachmentIntent.weight);
        technical.push("v2.79 attachment/file-trap intent: payload/message wording reviewed for fake attachment and shared-document lures.");
        timeline.push("v2.79 checked whether the payload was trying to move the user into opening a file, shared document, invoice, or macro-enabled content.");
      }
      const payloadPaymentIntent = inspectPaymentInvoiceScamIntent(target, payloadMessageContext);
      if (payloadPaymentIntent.active) {
        score -= payloadPaymentIntent.weight;
        const sample = payloadPaymentIntent.eTransferPattern ? "Interac/e-transfer or payment rail wording" : (payloadPaymentIntent.failedOrUnauthorized ? "failed/unauthorized/overdue payment wording" : (payloadPaymentIntent.paymentIntent[0] || "payment/invoice wording"));
        addSignal(signals, payloadPaymentIntent.severity, "Payment / invoice scam pattern", "The QR/message payload uses billing, invoice, refund, subscription, e-transfer, failed-payment, or unauthorized-charge language with action or pressure context. Evidence: " + sample + ". Verify payment claims through the official app, typed website, or known account channel before paying or entering card/bank details.", payloadPaymentIntent.weight);
        technical.push("v2.80 payment/invoice scam classifier: payload/message wording reviewed for payment pressure, fake billing, refund, and transfer lures.");
        timeline.push("v2.80 checked whether the payload was trying to move the user into payment, refund, subscription, or bank/card action.");
      }
      const payloadSubscriptionRenewalIntent = inspectSubscriptionRenewalScamIntent(target, payloadMessageContext);
      if (payloadSubscriptionRenewalIntent.active) {
        score -= payloadSubscriptionRenewalIntent.weight;
        const sample = payloadSubscriptionRenewalIntent.billingFailedPattern ? "billing/payment failed wording" : (payloadSubscriptionRenewalIntent.expiryCancelPattern ? "expiry/cancellation wording" : (payloadSubscriptionRenewalIntent.domainHostingPattern ? "domain/hosting renewal wording" : (payloadSubscriptionRenewalIntent.renewalActionPattern ? "renewal/update action wording" : (payloadSubscriptionRenewalIntent.intent[0] || "subscription renewal wording"))));
        addSignal(signals, payloadSubscriptionRenewalIntent.severity, "Subscription / account renewal scam pattern", "The QR/message payload uses subscription, renewal, billing-failed, payment-method, account-expiry, domain-renewal, or service-cancellation language with action or pressure context. Evidence: " + sample + ". Open the official service account directly before renewing, cancelling, updating payment details, or entering account information.", payloadSubscriptionRenewalIntent.weight);
        technical.push("v3.08 subscription/account-renewal classifier: payload/message wording reviewed for billing-failed, payment-method update, service-expiry, domain-renewal, and cancellation lures.");
        timeline.push("v3.08 checked whether the payload was trying to move the user into renewing, reactivating, cancelling, or updating subscription billing details.");
      }
      const payloadMoneyMovementIntent = inspectMoneyMovementScamIntent(target, payloadMessageContext);
      if (payloadMoneyMovementIntent.active) {
        score -= payloadMoneyMovementIntent.weight;
        const sample = payloadMoneyMovementIntent.transferRailPattern ? "transfer rail wording" : (payloadMoneyMovementIntent.refundDepositPattern ? "refund/deposit wording" : (payloadMoneyMovementIntent.verificationPattern ? "payment verification wording" : (payloadMoneyMovementIntent.reversalPattern ? "unauthorized/reversal wording" : (payloadMoneyMovementIntent.railWords[0] || "money movement wording"))));
        addSignal(signals, payloadMoneyMovementIntent.severity, "Money movement / payment rail scam pattern", "The QR/message payload uses refund, deposit, Interac/e-transfer, bank-transfer, recipient, payment-verification, or unauthorized-transaction language with action or pressure context. Evidence: " + sample + ". Verify through the official banking/payment app, typed website, or known account channel before accepting, sending, or releasing money.", payloadMoneyMovementIntent.weight);
        technical.push("v3.06 money-movement/payment-rail classifier: payload/message wording reviewed for refund, deposit, transfer, recipient, and payment-verification lures.");
        timeline.push("v3.06 checked whether the payload was trying to move the user into accepting, sending, reversing, or verifying a payment/transfer.");
      }
      const payloadDeliveryIntent = inspectDeliveryCustomsScamIntent(target, payloadMessageContext);
      if (payloadDeliveryIntent.active) {
        score -= payloadDeliveryIntent.weight;
        const sample = payloadDeliveryIntent.customsPattern ? "customs/duty fee wording" : (payloadDeliveryIntent.redeliveryPattern ? "failed or rescheduled delivery wording" : (payloadDeliveryIntent.addressPattern ? "address confirmation wording" : (payloadDeliveryIntent.carriers[0] || payloadDeliveryIntent.deliveryIntent[0] || "delivery/package wording")));
        addSignal(signals, payloadDeliveryIntent.severity, "Delivery / customs scam pattern", "The QR/message payload uses package, delivery, redelivery, tracking, customs, duty-fee, or address-confirmation language with action or pressure context. Evidence: " + sample + ". Verify delivery claims through the official carrier app, typed website, or known tracking channel before paying fees or entering personal details.", payloadDeliveryIntent.weight);
        technical.push("v2.81 delivery/customs scam classifier: QR/message payload checked for package, customs, tracking, redelivery, and address-confirmation lures.");
        timeline.push("v2.81 checked the QR/message payload for delivery, customs, package, tracking, or address-confirmation scam intent.");
      }
      const payloadParkingTollTransitIntent = inspectParkingTollTransitScamIntent(target, payloadMessageContext);
      if (payloadParkingTollTransitIntent.active) {
        score -= payloadParkingTollTransitIntent.weight;
        const sample = payloadParkingTollTransitIntent.tollPattern ? "toll/unpaid road-fee wording" : (payloadParkingTollTransitIntent.platePattern ? "plate or vehicle verification wording" : (payloadParkingTollTransitIntent.ticketPattern ? "ticket/fine/violation wording" : (payloadParkingTollTransitIntent.parkingQrPattern ? "parking/payment QR wording" : (payloadParkingTollTransitIntent.transitPattern ? "transit/fare wording" : (payloadParkingTollTransitIntent.intent[0] || "parking/toll/transit wording")))));
        addSignal(signals, payloadParkingTollTransitIntent.severity, "Parking / toll / transit scam pattern", "The QR/message payload uses parking, toll, transit, ticket, plate, vehicle, or violation-payment language with action or pressure context. Evidence: " + sample + ". Verify through the official parking meter/app, city/toll authority, or transit account before paying or entering plate/card details.", payloadParkingTollTransitIntent.weight);
        technical.push("v3.05 parking/toll/transit classifier: QR/message payload checked for parking-meter, toll-road, plate, ticket, citation, fare, and violation-payment lures.");
        timeline.push("v3.05 checked the QR/message payload for parking, toll, transit, ticket, plate, or vehicle-payment scam intent.");
      }
      const payloadGovernmentIntent = inspectGovernmentTaxLegalThreatIntent(target, payloadMessageContext);
      if (payloadGovernmentIntent.active) {
        score -= payloadGovernmentIntent.weight;
        const sample = payloadGovernmentIntent.legalThreatPattern ? "legal/fine/warrant pressure" : (payloadGovernmentIntent.taxRefundPattern ? "tax refund/revenue agency wording" : (payloadGovernmentIntent.benefitPattern ? "benefit/government payment wording" : (payloadGovernmentIntent.idCollectionPattern ? "identity/tax ID collection wording" : (payloadGovernmentIntent.intent[0] || "government/tax/legal wording"))));
        addSignal(signals, payloadGovernmentIntent.severity, "Government / tax / legal threat pattern", "The QR/message payload uses government, tax, benefit, fine, legal, warrant, or identity-verification language with action or pressure context. Evidence: " + sample + ". Verify through the official government website typed manually, a known phone number, or your existing account before paying fees, claiming benefits, uploading ID, or entering identity details.", payloadGovernmentIntent.weight);
        technical.push("v2.82 government/tax/legal classifier: QR/message payload checked for tax refund, benefits, fines, court/legal threats, and government impersonation pressure.");
        timeline.push("v2.82 checked the QR/message payload for government, tax, benefit, fine, legal, or identity-verification scam intent.");
      }
      const payloadFakeSecurityIntent = inspectFakeSecurityTechSupportIntent(target, payloadMessageContext);
      if (payloadFakeSecurityIntent.active) {
        score -= payloadFakeSecurityIntent.weight;
        const sample = payloadFakeSecurityIntent.remoteAccessPattern ? "remote-access/support-session wording" : (payloadFakeSecurityIntent.supportCallPattern ? "support-call/security phone wording" : (payloadFakeSecurityIntent.popupPattern ? "virus/device-infected warning" : (payloadFakeSecurityIntent.accountLockPattern ? "account/device locked warning" : (payloadFakeSecurityIntent.intent[0] || "security alert wording"))));
        addSignal(signals, payloadFakeSecurityIntent.severity, "Fake security alert / tech support pattern", "The QR/message payload uses virus, device-infected, account-locked, support-call, remote-access, or urgent security-warning language with action or pressure context. Evidence: " + sample + ". Do not call numbers, install tools, or grant remote access from an unsolicited alert; verify through the official app or typed website.", payloadFakeSecurityIntent.weight);
        technical.push("v2.83 fake security/tech-support classifier: QR/message payload checked for urgent security alert, support-call, remote-access, and device-infection lures.");
        timeline.push("v2.83 checked the QR/message payload for fake security alert or tech-support scam intent.");
      }
      const payloadJobIntent = inspectJobEmploymentScamIntent(target, payloadMessageContext);
      if (payloadJobIntent.active) {
        score -= payloadJobIntent.weight;
        const sample = payloadJobIntent.taskScamPattern ? "task-job/recharge/commission wording" : (payloadJobIntent.reshippingPattern ? "reshipping/package-forwarding wording" : (payloadJobIntent.feeToStartPattern ? "fee-to-start employment wording" : (payloadJobIntent.equipmentCheckPattern ? "equipment-check or reimbursement wording" : (payloadJobIntent.onboardingSensitivePattern ? "onboarding/payroll identity collection wording" : (payloadJobIntent.chatOnlyPattern ? "chat-only interview wording" : (payloadJobIntent.fakeOfferPattern ? "selected/job-offer wording" : (payloadJobIntent.intent[0] || "employment wording")))))));
        addSignal(signals, payloadJobIntent.severity, "Job / employment scam pattern", "The QR/message payload uses hiring, recruiter, remote-work, task-job, onboarding, payroll, equipment, reshipping, fee-to-start, or interview language with action or pressure context. Evidence: " + sample + ". Verify the employer through an official website, known HR channel, or established job platform before sharing identity, banking, or payment details.", payloadJobIntent.weight);
        technical.push("v3.11 job/recruitment classifier upgrade: QR/message payload checked for fake hiring, remote-work, task-job, onboarding, payroll, equipment-check, reshipping, fee-to-start, and chat-interview lures.");
        timeline.push("v2.84 checked the QR/message payload for job, recruitment, onboarding, payroll, equipment, or interview scam intent.");
      }
      const payloadModernIntents = inspectModernScamCoveragePack(target, payloadMessageContext);
      payloadModernIntents.forEach(intent => {
        score -= intent.weight;
        const titleMap = {
          "AI / family emergency impersonation":"AI / family emergency impersonation pattern",
          "Social media DM / influencer lure":"Social media DM / influencer scam pattern",
          "Marketplace buyer-seller scam":"Marketplace buyer-seller scam pattern",
          "Student / school portal scam":"Student / school portal scam pattern",
          "Fake recovery / report portal scam":"Fake recovery / report portal scam pattern"
        };
        addSignal(signals, intent.severity, titleMap[intent.key] || "Modern 2025/2026 scam pattern", "The QR/message payload matches the v3.12 modern threat pack: " + intent.detail + " Evidence: " + intent.sample + ".", intent.weight);
        technical.push("v3.12 modern scam coverage pack: QR/message payload checked for AI-family emergency, social DM, marketplace, student/school, and fake recovery/report portal lures.");
        timeline.push("v3.12 checked the QR/message payload against modern 2025/2026 scam patterns.");
      });
      const payloadCryptoIntent = inspectCryptoInvestmentScamIntent(target, payloadMessageContext);
      if (payloadCryptoIntent.active) {
        score -= payloadCryptoIntent.weight;
        const sample = payloadCryptoIntent.seedPhrasePattern ? "seed/private-key recovery wording" : (payloadCryptoIntent.walletConnectPattern ? "wallet connect/restore wording" : (payloadCryptoIntent.guaranteedReturnPattern ? "guaranteed-return wording" : (payloadCryptoIntent.recoveryFeePattern ? "recovery/unlock fee wording" : (payloadCryptoIntent.intent[0] || "crypto/investment wording"))));
        addSignal(signals, payloadCryptoIntent.severity, "Crypto / investment scam pattern", "The QR/message payload uses wallet, exchange, investment, profit, seed phrase, recovery, trading-bot, or guaranteed-return language with action, pressure, sensitive access, or fee context. Evidence: " + sample + ". Do not share seed phrases or private keys, and verify investments through official, typed channels before sending funds.", payloadCryptoIntent.weight);
        technical.push("v2.85 crypto/investment scam classifier: QR/message payload checked for wallet, seed phrase, fake profit, recovery-fee, exchange, and trading-bot lures.");
        timeline.push("v2.85 checked the QR/message payload for crypto, wallet, investment, recovery, or guaranteed-return scam intent.");
      }
      const payloadRomanceIntent = inspectRomanceTrustScamIntent(target, payloadMessageContext);
      if (payloadRomanceIntent.active) {
        score -= payloadRomanceIntent.weight;
        const sample = payloadRomanceIntent.privateLeveragePattern ? "private-photo/leverage wording" : (payloadRomanceIntent.emergencyMoneyPattern ? "emergency-money wording" : (payloadRomanceIntent.fakePersonaPattern ? "fake-persona travel/emergency wording" : (payloadRomanceIntent.moveOffPlatformPattern ? "move-off-platform wording" : (payloadRomanceIntent.intent[0] || "trust-building wording"))));
        addSignal(signals, payloadRomanceIntent.severity, "Romance / trust-building social engineering pattern", "The QR/message payload uses relationship, friendship, private-chat, emergency, gift-card, travel-fee, or emotional trust-building language with money, pressure, sensitive, or off-platform context. Evidence: " + sample + ". Do not send money, gift cards, crypto, private photos, or identity details to someone you have not independently verified.", payloadRomanceIntent.weight);
        technical.push("v2.86 romance/trust-building classifier: QR/message payload checked for emotional trust-building, move-off-platform, emergency-money, gift-card, and private-photo leverage lures.");
        timeline.push("v2.86 checked the QR/message payload for romance, friendship, trust-building, emergency-money, or private-chat scam intent.");
      }
      const payloadMfaOtpIntent = inspectMfaOtpCodeTheft(target, payloadMessageContext);
      if (payloadMfaOtpIntent.active) {
        score -= payloadMfaOtpIntent.weight;
        const sample = payloadMfaOtpIntent.codeHarvestPattern ? "one-time code sharing pattern" : (payloadMfaOtpIntent.pushApprovalPattern ? "push approval/login approval pattern" : (payloadMfaOtpIntent.recoveryCodePattern ? "backup/recovery code pattern" : (payloadMfaOtpIntent.intent[0] || "code-theft wording")));
        addSignal(signals, payloadMfaOtpIntent.severity, "MFA / OTP code theft pattern", "The QR/message payload asks for or steers the user toward sharing, entering, approving, or forwarding one-time codes, authenticator prompts, backup codes, or login approval requests. Evidence: " + sample + ". Never share one-time codes or approve login prompts unless you personally initiated the login through a known official route.", payloadMfaOtpIntent.weight);
        technical.push("v2.99 MFA/OTP code theft classifier: QR/message payload checked for one-time-code, authenticator, approval-prompt, and recovery-code lures.");
        timeline.push("v2.99 checked whether the QR/message payload was trying to steal or trigger an MFA, OTP, authenticator, or login approval action.");
      }
      const payloadAccountRecoveryIntent = inspectAccountRecoveryTakeover(target, payloadMessageContext);
      if (payloadAccountRecoveryIntent.active) {
        score -= payloadAccountRecoveryIntent.weight;
        const sample = payloadAccountRecoveryIntent.passwordResetPattern ? "password-reset/account recovery wording" : (payloadAccountRecoveryIntent.recoveryLinkPattern ? "recovery-link/unlock wording" : (payloadAccountRecoveryIntent.changeAlertPattern ? "account/device change alert wording" : (payloadAccountRecoveryIntent.intent[0] || "account recovery wording")));
        addSignal(signals, payloadAccountRecoveryIntent.severity, "Account Recovery / Password Reset Takeover pattern", "The QR/message payload asks the user to reset, recover, unlock, reactivate, approve, or change account access in a way that could lead to account takeover. Evidence: " + sample + ". Do not use recovery or reset links from unexpected messages; go directly to the official app or typed website.", payloadAccountRecoveryIntent.weight);
        technical.push("v3.00 account recovery/password reset takeover classifier: QR/message payload checked for password-reset, account-recovery, unlock/reactivation, device-change, and recovery-link lures.");
        timeline.push("v3.00 checked whether the QR/message payload was trying to move the user into an account recovery or password reset takeover flow.");
      }
      const payloadUrgencyIntent = inspectUrgencyPressureTactic(target, payloadMessageContext);
      if (payloadUrgencyIntent.active) {
        score -= payloadUrgencyIntent.weight;
        const sample = payloadUrgencyIntent.fearPressurePattern ? "fear/final-notice pressure" : (payloadUrgencyIntent.countdownPattern ? "deadline/countdown pressure" : (payloadUrgencyIntent.actionNowPattern ? "act-now wording" : (payloadUrgencyIntent.pressure[0] || "urgency pressure")));
        addSignal(signals, payloadUrgencyIntent.severity, "Urgency / pressure tactic pattern", "The QR/message payload uses countdown, final-notice, act-now, penalty, suspension, or fear-pressure language alongside action or sensitive context. Evidence: " + sample + ". Slow down and verify through a separate trusted route before clicking, calling, paying, or entering information.", payloadUrgencyIntent.weight);
        technical.push("v2.97 urgency/pressure classifier: QR/message payload checked for countdown, final-notice, act-now, and fear-pressure scam tactics.");
        timeline.push("v2.97 checked whether the QR/message payload was using urgency or fear to push fast action.");
      }
      const payloadAuthorityIntent = inspectAuthorityImpersonationVoice(target, payloadMessageContext);
      if (payloadAuthorityIntent.active) {
        score -= payloadAuthorityIntent.weight;
        const sample = payloadAuthorityIntent.departmentPersonaPattern ? "department/team persona wording" : (payloadAuthorityIntent.officialNoticePattern ? "official notice/case reference wording" : (payloadAuthorityIntent.authorityPlusActionPattern ? "authority plus action wording" : (payloadAuthorityIntent.identities[0] || payloadAuthorityIntent.claims[0] || "authority wording")));
        addSignal(signals, payloadAuthorityIntent.severity, "Authority / impersonation voice pattern", "The QR/message payload uses official-sounding department, case, reference, compliance, review, or support-team language alongside action, pressure, sensitive context, or brand mismatch. Evidence: " + sample + ". Verify through a known channel instead of trusting the claimed authority inside the message.", payloadAuthorityIntent.weight);
        technical.push("v2.98 authority/impersonation voice classifier: QR/message payload checked for official notice, department persona, case/reference, compliance, and review tactics.");
        timeline.push("v2.98 checked whether the QR/message payload was borrowing authority language to pressure action.");
      }
      if (payload.workflowHits && payload.workflowHits.length >= 3) addSignal(signals, "medium", "Sensitive words in payload", "Found terms: " + payload.workflowHits.slice(0,6).join(", ") + ".", 10);
      trust.push("Payload mode: no web root was assumed.");
      technical.push("Payload length: " + target.raw.length + " characters.");
      technical.push("Payload classification: " + payload.kind + ".");
      if (payload.prefix) technical.push("Structured payload prefix: " + payload.prefix + ".");
      timeline.push("Proxuma separated QR/text payloads from normal URL risk scoring and classified the payload type first.");
      return finalize({target, score, signals, technical, trust, timeline});
    }

    const host = target.host;
    const root = target.root;
    const path = target.path.toLowerCase();
    const allText = (host + " " + path).toLowerCase();
    const subdomainDepth = Math.max(0, host.split(".").length - root.split(".").length);
    const isTrusted = trustedRoots.has(root) || Array.from(trustedRoots).some(r => root === r || host.endsWith("." + r));
    const bankFamily = matchingTrustedFamily(root);
    const brands = findBrandMentions(host, path);
    const trustedShareWrapper = classifyTrustedShareWrapper(target);

    trust.push("Scheme, host, root domain, subdomains, wording, file pattern, TLD, and known-family checks completed locally.");
    timeline.push("True target extracted: " + root + ".");
    if (target.normalizationNotes && target.normalizationNotes.length) {
      const extracted = target.normalizationNotes.some(note => /extracted/i.test(note));
      addSignal(signals, extracted ? "medium" : "low", extracted ? "URL extracted from surrounding text" : "Input boundary normalized", target.normalizationNotes.join(" "), extracted ? 8 : 0);
      target.normalizationNotes.forEach(note => technical.push("Input normalization: " + note));
      if (extracted) timeline.push("Surrounding text was separated from the real URL before scoring.");
    }

    if (trustedShareWrapper.active) {
      score -= trustedShareWrapper.weight;
      addSignal(signals, trustedShareWrapper.severity, trustedShareWrapper.title, trustedShareWrapper.detail, trustedShareWrapper.weight);
      technical.push("v2.71 trusted share-wrapper intelligence: " + trustedShareWrapper.mode + ".");
      timeline.push("v2.71 separated trusted wrapper ownership from final-destination confidence.");
      if (trustedShareWrapper.mode !== "readable-destination") {
        score -= 8;
        addSignal(signals, "medium", "Final destination not visible offline", "The wrapper owner is recognized, but the offline scan cannot prove the landing page behind the token. Verify the destination before entering credentials, payments, or personal information.", 8);
      }
    }

    const messageContext = analyzeMessageContext(target.sourceRaw || target.raw, target.embeddedCandidates || [], root);
    if (messageContext.envelope !== "Direct target") {
      technical.push("Message intelligence envelope: " + messageContext.envelope + ".");
      if (messageContext.candidates.length) technical.push("Message intelligence URL count: " + messageContext.candidates.length + ".");
      if (messageContext.pressure.length) technical.push("Message pressure wording: " + messageContext.pressure.slice(0,8).join(", ") + ".");
      timeline.push("v2.52 reviewed surrounding message context before final scoring.");
    }
    const htmlArtifacts = inspectHtmlEmailArtifacts(target.sourceRaw || target.raw);
    if (htmlArtifacts.isHtml) {
      technical.push("v2.58 HTML email intelligence: HTML/snippet patterns detected.");
      timeline.push("v2.58 inspected copied email/page HTML before final judgment.");
      if (htmlArtifacts.anchors.length > 1) addSignal(signals,"medium","Multiple HTML links in copied content","The pasted HTML/email block contains " + htmlArtifacts.anchors.length + " link anchors. Review every destination, not only the visible button or first link.",12);
      if (htmlArtifacts.buttonLike || htmlArtifacts.imageLinks) addSignal(signals,"medium","Button/image link in copied email","The content uses a button-like or image-based link. Scam emails often hide the true URL behind friendly buttons or images.",10);
      if (htmlArtifacts.forms.length) addSignal(signals,"high","HTML form submits to a web destination","The copied content includes a form action. Forms can collect credentials or payment details, so treat unsolicited login/payment forms as unsafe.",22);
      if (htmlArtifacts.metaRefresh.length) addSignal(signals,"high","HTML meta refresh redirect","The copied content includes a meta refresh redirect. This can move the browser to another destination without a normal click.",22);
      if (htmlArtifacts.scriptRedirects.length) addSignal(signals,"high","JavaScript redirect snippet","The copied content includes script-style redirection. Offline Proxuma treats copied redirect code as a strong warning sign.",22);
      if (htmlArtifacts.hidden.length) addSignal(signals,"medium","Hidden or invisible HTML content","The copied content contains hidden-display styling (" + Array.from(new Set(htmlArtifacts.hidden)).join(", ") + "). Hidden content can conceal links, warnings, or tracking elements.",14);
      if (htmlArtifacts.hidden.length && htmlArtifacts.anchors.length) addSignal(signals,"high","Hidden HTML link present","The copied HTML contains hidden styling plus at least one link. Hidden links can conceal a destination from the person reading the message.",22);
    }
    if (messageContext.candidates.length > 1) {
      score -= 12;
      addSignal(signals,"medium","Multiple links in one message","The pasted message contains " + messageContext.candidates.length + " link-like targets. Proxuma scans the active destination but recommends reviewing every link in the original message before clicking.",12);
    }
    if (messageContext.pressure.length >= 2) {
      score -= 12;
      addSignal(signals,"medium","Message pressure tactics","The surrounding message uses pressure or action wording: " + messageContext.pressure.slice(0,6).join(", ") + ". Scams often pair urgency with a link.",12);
    } else if (messageContext.pressure.length === 1 && messageContext.envelope !== "Direct target") {
      score -= 5;
      addSignal(signals,"low","Message action wording","The surrounding message includes action wording: " + messageContext.pressure[0] + ". This is a context signal, not proof by itself.",5);
    }
    if (messageContext.mismatchedBrands.length) {
      const readable = messageContext.mismatchedBrands.slice(0,3).map(hit => hit.family + " via '" + hit.hint + "'").join(", ");
      score -= 22;
      addSignal(signals,"high","Message brand / destination mismatch","The surrounding message mentions a trusted brand (" + readable + "), but the active destination resolves to " + root + ". Trust the real root domain, not the message wording.",22);
      timeline.push("Message wording was compared against the real destination; a trusted-brand mismatch was found.");
    }
    if (messageContext.highRiskCandidates.length && messageContext.candidates.length > 1) {
      const sample = messageContext.highRiskCandidates[0];
      score -= 18;
      addSignal(signals,"high","Risky link hidden among multiple links","At least one link inside the pasted message looks risky (sample root: " + sample.root + "). Attack messages may include one safe-looking link beside one harmful destination.",18);
    }

    const credentialIntent = inspectCredentialHarvestIntent(target, messageContext);
    if (credentialIntent.active && !credentialIntent.rootedTrusted) {
      const groupSummary = [];
      if (credentialIntent.groups.credential.length) groupSummary.push("credential words: " + credentialIntent.groups.credential.slice(0,5).join(", "));
      if (credentialIntent.groups.collection.length) groupSummary.push("collection/action words: " + credentialIntent.groups.collection.slice(0,4).join(", "));
      if (credentialIntent.groups.financial.length) groupSummary.push("financial words: " + credentialIntent.groups.financial.slice(0,4).join(", "));
      if (credentialIntent.groups.credentialParams.length) groupSummary.push("credential parameters: " + credentialIntent.groups.credentialParams.slice(0,5).join(", "));
      const strongSecretTerms = credentialIntent.groups.credential.some(word => /^(password|passwd|pwd|otp|2fa|mfa|pin|credential|credentials)$/.test(word));
      const highIntent = credentialIntent.hasImpersonationContext || strongSecretTerms || credentialIntent.groups.financial.length > 0 || (credentialIntent.groups.collection.length > 0 && credentialIntent.groups.credential.length >= 2) || ((messageContext.pressure || []).length >= 2 && credentialIntent.groups.credential.length >= 1);
      const severity = highIntent ? "high" : "medium";
      const weight = highIntent ? 24 : 12;
      score -= weight;
      addSignal(signals,severity,"Credential-harvest intent pattern","The target combines login/account/security language with collection, password/token, financial, pressure, or brand-mismatch context on a non-trusted root. Evidence: " + (groupSummary.join("; ") || "credential-intent density " + credentialIntent.credentialDensity) + ". Do not enter credentials or one-time codes from this link.",weight);
      technical.push("v2.66 credential-harvest intent: non-trusted root with credential collection indicators" + (highIntent ? "." : " treated as review, not automatic high risk."));
      timeline.push("v2.66 checked whether the link was trying to collect credentials, one-time codes, or account access.");
    } else if (credentialIntent.active && credentialIntent.rootedTrusted) {
      addSignal(signals,"low","Credential workflow on known root","Login/account/security wording appears on a known local trusted root. Proxuma records the workflow context without treating it as impersonation by itself.",-2);
      technical.push("v2.66 credential-harvest intent: trusted-root relief kept credential workflow from escalating.");
    }
    const callbackIntent = inspectCallbackScamIntent(target, messageContext);
    if (callbackIntent.active) {
      score -= callbackIntent.weight;
      const phoneSample = callbackIntent.phones.length ? " Phone clue: " + callbackIntent.phones[0] + "." : "";
      addSignal(signals, callbackIntent.severity, "Callback scam intent pattern", "The message or target pushes the user toward a phone/support contact while also carrying pressure, account, payment, refund, delivery, tax, or security context." + phoneSample + " Verify through an official app, typed website, or known phone number instead of the message.", callbackIntent.weight);
      technical.push("v2.78 callback scam intent: phone-first social-engineering pattern checked locally.");
      timeline.push("v2.78 checked callback/support scam intent before final advice.");
    }
    const attachmentIntent = inspectAttachmentFileTrapIntent(target, messageContext);
    if (attachmentIntent.active) {
      score -= attachmentIntent.weight;
      const evidenceBits = [];
      if (attachmentIntent.macroWords.length) evidenceBits.push("macro/content prompt: " + attachmentIntent.macroWords.slice(0,3).join(", "));
      if (attachmentIntent.executableHits.length) evidenceBits.push("risky file type: " + attachmentIntent.executableHits.slice(0,3).join(", "));
      if (attachmentIntent.archiveHits.length) evidenceBits.push("archive file: " + attachmentIntent.archiveHits.slice(0,3).join(", "));
      if (attachmentIntent.cloudBrands.length) evidenceBits.push("cloud/e-sign lure: " + attachmentIntent.cloudBrands.slice(0,3).join(", "));
      if (attachmentIntent.fileIntent.length) evidenceBits.push("file wording: " + attachmentIntent.fileIntent.slice(0,4).join(", "));
      addSignal(signals, attachmentIntent.severity, "Attachment / file trap intent", "The message or target uses invoice, shared-document, cloud-file, e-signature, macro, or file-opening language that can push a user into opening something risky. Evidence: " + (evidenceBits.join("; ") || "file-trap density " + attachmentIntent.lureDensity) + ". Verify through the official account or known sender before opening or downloading.", attachmentIntent.weight);
      technical.push("v2.79 attachment/file-trap intent: URL/message lane checked for fake attachment, shared-document, invoice, and macro lures.");
      timeline.push("v2.79 checked whether the target was trying to make the user open a file, invoice, shared document, or macro-enabled content.");
    }
    const paymentIntent = inspectPaymentInvoiceScamIntent(target, messageContext);
    if (paymentIntent.active) {
      score -= paymentIntent.weight;
      const evidenceBits = [];
      if (paymentIntent.eTransferPattern) evidenceBits.push("transfer rail wording");
      if (paymentIntent.failedOrUnauthorized) evidenceBits.push("failed/unauthorized/overdue payment wording");
      if (paymentIntent.paymentIntent.length) evidenceBits.push("payment words: " + paymentIntent.paymentIntent.slice(0,5).join(", "));
      if (paymentIntent.actions.length) evidenceBits.push("action words: " + paymentIntent.actions.slice(0,4).join(", "));
      if (paymentIntent.sensitive.length) evidenceBits.push("sensitive payment/account words: " + paymentIntent.sensitive.slice(0,4).join(", "));
      addSignal(signals, paymentIntent.severity, "Payment / invoice scam pattern", "The message or target combines billing, invoice, refund, subscription, e-transfer, failed-payment, unauthorized-charge, or payment-method language with action, pressure, sensitive account, or mismatch context. Evidence: " + (evidenceBits.join("; ") || "payment density " + paymentIntent.density) + ". Verify through the official app, typed website, or known account channel before paying or entering card/bank details.", paymentIntent.weight);
      technical.push("v2.80 payment/invoice scam classifier: URL/message lane checked for fake billing, refund, subscription, e-transfer, and unauthorized-charge lures.");
      timeline.push("v2.80 checked whether the target was trying to move the user into a payment, refund, subscription, transfer, or billing-update action.");
    }
    const moneyMovementIntent = inspectMoneyMovementScamIntent(target, messageContext);
    if (moneyMovementIntent.active) {
      score -= moneyMovementIntent.weight;
      const evidenceBits = [];
      if (moneyMovementIntent.transferRailPattern) evidenceBits.push("transfer rail wording");
      if (moneyMovementIntent.refundDepositPattern) evidenceBits.push("refund/deposit wording");
      if (moneyMovementIntent.recipientPattern) evidenceBits.push("recipient/payee wording");
      if (moneyMovementIntent.verificationPattern) evidenceBits.push("payment verification wording");
      if (moneyMovementIntent.reversalPattern) evidenceBits.push("unauthorized/reversal wording");
      if (moneyMovementIntent.railWords.length) evidenceBits.push("rail words: " + moneyMovementIntent.railWords.slice(0,5).join(", "));
      if (moneyMovementIntent.actions.length) evidenceBits.push("action words: " + moneyMovementIntent.actions.slice(0,4).join(", "));
      if (moneyMovementIntent.sensitive.length) evidenceBits.push("bank/payment details: " + moneyMovementIntent.sensitive.slice(0,4).join(", "));
      addSignal(signals, moneyMovementIntent.severity, "Money movement / payment rail scam pattern", "The message or target combines refund, deposit, Interac/e-transfer, bank-transfer, recipient, payment-verification, or unauthorized-transaction language with action, pressure, sensitive details, or mismatch context. Evidence: " + (evidenceBits.join("; ") || "money-movement density " + moneyMovementIntent.density) + ". Verify through the official banking/payment app, typed website, or known account channel before accepting, sending, reversing, or releasing money.", moneyMovementIntent.weight);
      technical.push("v3.06 money-movement/payment-rail classifier: URL/message lane checked for refund, deposit, transfer, recipient, payment-verification, and unauthorized-transaction lures.");
      timeline.push("v3.06 checked whether the target was trying to move the user into accepting, sending, reversing, or verifying a payment/transfer.");
    }
    const giftPrizeRewardIntent = inspectGiftPrizeRewardScamIntent(target, messageContext);
    if (giftPrizeRewardIntent.active) {
      score -= giftPrizeRewardIntent.weight;
      const evidenceBits = [];
      if (giftPrizeRewardIntent.giftCardPurchasePattern) evidenceBits.push("gift/prepaid-card purchase or sharing wording");
      if (giftPrizeRewardIntent.prizeClaimPattern) evidenceBits.push("winner/prize claim wording");
      if (giftPrizeRewardIntent.loyaltyPointsPattern) evidenceBits.push("loyalty/reward points wording");
      if (giftPrizeRewardIntent.feeToClaimPattern) evidenceBits.push("fee-to-claim wording");
      if (giftPrizeRewardIntent.intent.length) evidenceBits.push("reward words: " + giftPrizeRewardIntent.intent.slice(0,5).join(", "));
      if (giftPrizeRewardIntent.actions.length) evidenceBits.push("action words: " + giftPrizeRewardIntent.actions.slice(0,4).join(", "));
      if (giftPrizeRewardIntent.sensitive.length) evidenceBits.push("code/card/account words: " + giftPrizeRewardIntent.sensitive.slice(0,4).join(", "));
      addSignal(signals, giftPrizeRewardIntent.severity, "Gift card / prize / reward claim scam pattern", "The message or target combines gift-card, voucher, prize, giveaway, loyalty-points, reward, or cashback language with claim, redeem, pressure, payment, code, card, or mismatch context. Evidence: " + (evidenceBits.join("; ") || "gift/prize/reward density " + giftPrizeRewardIntent.density) + ". Verify through the official rewards account or typed website before buying, sending, uploading, redeeming, or entering gift-card/reward details.", giftPrizeRewardIntent.weight);
      technical.push("v3.07 gift-card/prize/reward classifier: URL/message lane checked for gift-card, prize, loyalty-points, reward, voucher, and fee-to-claim lures.");
      timeline.push("v3.07 checked whether the target was trying to move the user into buying, sending, uploading, redeeming, or verifying gift cards, prizes, rewards, or loyalty points.");
    }
    const subscriptionRenewalIntent = inspectSubscriptionRenewalScamIntent(target, messageContext);
    if (subscriptionRenewalIntent.active) {
      score -= subscriptionRenewalIntent.weight;
      const evidenceBits = [];
      if (subscriptionRenewalIntent.billingFailedPattern) evidenceBits.push("billing/payment failed wording");
      if (subscriptionRenewalIntent.expiryCancelPattern) evidenceBits.push("expiry/cancellation/suspension wording");
      if (subscriptionRenewalIntent.renewalActionPattern) evidenceBits.push("renewal/update action wording");
      if (subscriptionRenewalIntent.domainHostingPattern) evidenceBits.push("domain/hosting renewal wording");
      if (subscriptionRenewalIntent.intent.length) evidenceBits.push("subscription words: " + subscriptionRenewalIntent.intent.slice(0,5).join(", "));
      if (subscriptionRenewalIntent.actions.length) evidenceBits.push("action words: " + subscriptionRenewalIntent.actions.slice(0,4).join(", "));
      if (subscriptionRenewalIntent.sensitive.length) evidenceBits.push("billing/account words: " + subscriptionRenewalIntent.sensitive.slice(0,4).join(", "));
      addSignal(signals, subscriptionRenewalIntent.severity, "Subscription / account renewal scam pattern", "The message or target combines subscription, renewal, billing-failed, payment-method, account-expiry, service-cancellation, storage, license, domain, or hosting language with action, pressure, sensitive information, or mismatch context. Evidence: " + (evidenceBits.join("; ") || "subscription-renewal density " + subscriptionRenewalIntent.density) + ". Open the official service account directly before renewing, cancelling, updating payment details, or entering account information.", subscriptionRenewalIntent.weight);
      technical.push("v3.08 subscription/account-renewal classifier: URL/message lane checked for billing-failed, payment-method update, service-expiry, account cancellation, storage, license, domain-renewal, and hosting-renewal lures.");
      timeline.push("v3.08 checked whether the target was trying to move the user into renewing, reactivating, cancelling, or updating subscription billing details.");
    }
    const deliveryIntent = inspectDeliveryCustomsScamIntent(target, messageContext);
    if (deliveryIntent.active) {
      score -= deliveryIntent.weight;
      const evidenceBits = [];
      if (deliveryIntent.carriers.length) evidenceBits.push("carrier wording: " + deliveryIntent.carriers.slice(0,4).join(", "));
      if (deliveryIntent.customsPattern) evidenceBits.push("customs/duty fee wording");
      if (deliveryIntent.parcelFeePattern) evidenceBits.push("parcel/delivery fee collection wording");
      if (deliveryIntent.redeliveryPattern) evidenceBits.push("failed/redelivery wording");
      if (deliveryIntent.missedSignaturePattern) evidenceBits.push("missed signature/recipient action wording");
      if (deliveryIntent.trackingPortalPattern) evidenceBits.push("tracking/parcel portal wording");
      if (deliveryIntent.addressPattern) evidenceBits.push("address confirmation wording");
      if (deliveryIntent.feeWords.length) evidenceBits.push("fee words: " + deliveryIntent.feeWords.slice(0,4).join(", "));
      if (deliveryIntent.portalWords.length) evidenceBits.push("portal words: " + deliveryIntent.portalWords.slice(0,4).join(", "));
      if (deliveryIntent.deliveryIntent.length) evidenceBits.push("delivery words: " + deliveryIntent.deliveryIntent.slice(0,5).join(", "));
      if (deliveryIntent.actions.length) evidenceBits.push("action words: " + deliveryIntent.actions.slice(0,4).join(", "));
      if (deliveryIntent.sensitive.length) evidenceBits.push("sensitive delivery/payment words: " + deliveryIntent.sensitive.slice(0,4).join(", "));
      addSignal(signals, deliveryIntent.severity, "Delivery / customs scam pattern", "The message or target combines package, delivery, tracking, customs, duty-fee, redelivery, carrier, parcel-fee, missed-signature, tracking-portal, or address-confirmation language with action, pressure, sensitive information, or mismatch context. Evidence: " + (evidenceBits.join("; ") || "delivery density " + deliveryIntent.density) + ". Verify through the official carrier app, typed website, or known tracking channel before paying fees, correcting addresses, rescheduling deliveries, or entering personal details.", deliveryIntent.weight);
      technical.push("v3.09 delivery/parcel/courier classifier upgrade: URL/message lane checked for fake package, customs, parcel-fee, tracking-portal, missed-signature, redelivery, and address-confirmation lures.");
      timeline.push("v3.09 checked whether the target was trying to move the user into a delivery, customs, package-release, tracking, payment, redelivery, or address-confirmation action.");
    }
    const parkingTollTransitIntent = inspectParkingTollTransitScamIntent(target, messageContext);
    if (parkingTollTransitIntent.active) {
      score -= parkingTollTransitIntent.weight;
      const evidenceBits = [];
      if (parkingTollTransitIntent.tollPattern) evidenceBits.push("toll or unpaid road-fee wording");
      if (parkingTollTransitIntent.platePattern) evidenceBits.push("plate/vehicle verification wording");
      if (parkingTollTransitIntent.ticketPattern) evidenceBits.push("ticket/fine/violation wording");
      if (parkingTollTransitIntent.parkingQrPattern) evidenceBits.push("parking meter/payment wording");
      if (parkingTollTransitIntent.transitPattern) evidenceBits.push("transit/fare wording");
      if (parkingTollTransitIntent.intent.length) evidenceBits.push("mobility words: " + parkingTollTransitIntent.intent.slice(0,5).join(", "));
      if (parkingTollTransitIntent.actions.length) evidenceBits.push("action words: " + parkingTollTransitIntent.actions.slice(0,4).join(", "));
      if (parkingTollTransitIntent.sensitive.length) evidenceBits.push("plate/payment/account words: " + parkingTollTransitIntent.sensitive.slice(0,4).join(", "));
      addSignal(signals, parkingTollTransitIntent.severity, "Parking / toll / transit scam pattern", "The message or target combines parking, toll-road, transit, ticket, citation, plate, vehicle, or violation-payment language with action, pressure, sensitive information, or mismatch context. Evidence: " + (evidenceBits.join("; ") || "mobility-payment density " + parkingTollTransitIntent.density) + ". Verify through the official parking meter/app, city/toll authority, or transit account before paying fees or entering plate/card details.", parkingTollTransitIntent.weight);
      technical.push("v3.05 parking/toll/transit classifier: URL/message lane checked for parking-meter, toll-road, transit-fare, ticket, citation, plate, and vehicle-payment lures.");
      timeline.push("v3.05 checked whether the target was trying to move the user into a parking, toll, transit, ticket, plate, or vehicle-payment action.");
    }
    const governmentIntent = inspectGovernmentTaxLegalThreatIntent(target, messageContext);
    if (governmentIntent.active) {
      score -= governmentIntent.weight;
      const evidenceBits = [];
      if (governmentIntent.taxRefundPattern) evidenceBits.push("tax refund/revenue agency wording");
      if (governmentIntent.benefitPattern) evidenceBits.push("benefit/government payment wording");
      if (governmentIntent.legalThreatPattern) evidenceBits.push("legal/fine/warrant pressure");
      if (governmentIntent.idCollectionPattern) evidenceBits.push("identity/tax ID collection wording");
      if (governmentIntent.immigrationLicensePattern) evidenceBits.push("immigration/license/permit wording");
      if (governmentIntent.agencyPortalPattern) evidenceBits.push("agency portal/account verification wording");
      if (governmentIntent.overpaymentPattern) evidenceBits.push("overpayment/arrears/reassessment wording");
      if (governmentIntent.intent.length) evidenceBits.push("government/legal words: " + governmentIntent.intent.slice(0,5).join(", "));
      if (governmentIntent.actions.length) evidenceBits.push("action words: " + governmentIntent.actions.slice(0,4).join(", "));
      if (governmentIntent.sensitive.length) evidenceBits.push("sensitive identity/account words: " + governmentIntent.sensitive.slice(0,4).join(", "));
      addSignal(signals, governmentIntent.severity, "Government / tax / legal threat pattern", "The message or target combines government, tax, benefit, agency-portal, immigration, license, fine, legal, warrant, court, overpayment, or identity-verification language with action, pressure, sensitive information, or mismatch context. Evidence: " + (evidenceBits.join("; ") || "government/legal density " + governmentIntent.density) + ". Verify through the official government website typed manually, a known phone number, or your existing account before paying fees, claiming benefits, uploading ID, or entering identity details.", governmentIntent.weight);
      technical.push("v3.10 government/tax/benefit classifier upgrade: URL/message lane checked for tax refunds, benefits, ID collection, agency portals, immigration/license/permit, overpayment, fines, court/legal threats, warrants, and government impersonation pressure.");
      timeline.push("v3.10 checked whether the target was trying to move the user into a government, tax, benefit, legal, identity, immigration, license, or agency-portal action.");
    }
    const fakeSecurityIntent = inspectFakeSecurityTechSupportIntent(target, messageContext);
    if (fakeSecurityIntent.active) {
      score -= fakeSecurityIntent.weight;
      const evidenceBits = [];
      if (fakeSecurityIntent.popupPattern) evidenceBits.push("virus/device-infected warning");
      if (fakeSecurityIntent.supportCallPattern) evidenceBits.push("support-call/security phone wording");
      if (fakeSecurityIntent.remoteAccessPattern) evidenceBits.push("remote-access/support-session wording");
      if (fakeSecurityIntent.accountLockPattern) evidenceBits.push("account/device locked warning");
      if (fakeSecurityIntent.intent.length) evidenceBits.push("security words: " + fakeSecurityIntent.intent.slice(0,5).join(", "));
      if (fakeSecurityIntent.actions.length) evidenceBits.push("action words: " + fakeSecurityIntent.actions.slice(0,4).join(", "));
      if (fakeSecurityIntent.sensitive.length) evidenceBits.push("sensitive/access words: " + fakeSecurityIntent.sensitive.slice(0,4).join(", "));
      addSignal(signals, fakeSecurityIntent.severity, "Fake security alert / tech support pattern", "The message or target combines virus, malware, device-infected, account-locked, support-call, remote-access, or urgent security-warning language with action, pressure, sensitive access, or mismatch context. Evidence: " + (evidenceBits.join("; ") || "security-alert density " + fakeSecurityIntent.density) + ". Do not call numbers, install tools, or grant remote access from an unsolicited alert; verify through the official app, typed website, or known support channel.", fakeSecurityIntent.weight);
      technical.push("v2.83 fake security/tech-support classifier: URL/message lane checked for urgent security alert, support-call, remote-access, device-infection, and account-lock lures.");
      timeline.push("v2.83 checked whether the target was trying to move the user into a fake security alert or tech-support action.");
    }


    const jobIntent = inspectJobEmploymentScamIntent(target, messageContext);
    if (jobIntent.active) {
      score -= jobIntent.weight;
      const evidenceBits = [];
      if (jobIntent.remoteWorkPattern) evidenceBits.push("remote/work-from-home wording");
      if (jobIntent.fakeOfferPattern) evidenceBits.push("selected/job-offer wording");
      if (jobIntent.equipmentCheckPattern) evidenceBits.push("equipment-check or reimbursement wording");
      if (jobIntent.onboardingSensitivePattern) evidenceBits.push("onboarding/payroll identity collection wording");
      if (jobIntent.chatOnlyPattern) evidenceBits.push("chat-only interview wording");
      if (jobIntent.taskScamPattern) evidenceBits.push("task-job/recharge/commission wording");
      if (jobIntent.reshippingPattern) evidenceBits.push("reshipping/package-forwarding wording");
      if (jobIntent.feeToStartPattern) evidenceBits.push("fee-to-start employment wording");
      if (jobIntent.intent.length) evidenceBits.push("employment words: " + jobIntent.intent.slice(0,5).join(", "));
      if (jobIntent.money.length) evidenceBits.push("money/equipment words: " + jobIntent.money.slice(0,4).join(", "));
      if (jobIntent.sensitive.length) evidenceBits.push("sensitive hiring words: " + jobIntent.sensitive.slice(0,4).join(", "));
      addSignal(signals, jobIntent.severity, "Job / employment scam pattern", "The message or target combines hiring, recruiter, remote-work, task-job, onboarding, payroll, equipment, reshipping, interview, fee-to-start, or job-offer language with action, pressure, sensitive identity/banking, money, or mismatch context. Evidence: " + (evidenceBits.join("; ") || "employment density " + jobIntent.density) + ". Verify the employer through an official website, known HR channel, or established job platform before sharing identity, banking, or payment details.", jobIntent.weight);
      technical.push("v3.11 job/recruitment classifier upgrade: URL/message lane checked for fake recruiter, remote-work, task-job, onboarding, payroll, equipment-check, reshipping, fee-to-start, mystery-shopper, and interview lures.");
      timeline.push("v2.84 checked whether the target was trying to move the user into a job, recruitment, onboarding, payroll, equipment, or interview scam flow.");
    }

    const modernIntents = inspectModernScamCoveragePack(target, messageContext);
    modernIntents.forEach(intent => {
      score -= intent.weight;
      const titleMap = {
        "AI / family emergency impersonation":"AI / family emergency impersonation pattern",
        "Social media DM / influencer lure":"Social media DM / influencer scam pattern",
        "Marketplace buyer-seller scam":"Marketplace buyer-seller scam pattern",
        "Student / school portal scam":"Student / school portal scam pattern",
        "Fake recovery / report portal scam":"Fake recovery / report portal scam pattern"
      };
      addSignal(signals, intent.severity, titleMap[intent.key] || "Modern 2025/2026 scam pattern", "The message or target matches the v3.12 modern threat pack: " + intent.detail + " Evidence: " + intent.sample + ".", intent.weight);
      technical.push("v3.12 modern scam coverage pack: URL/message lane checked for AI-family emergency, social DM, marketplace, student/school, and fake recovery/report portal lures.");
      timeline.push("v3.12 checked the target against modern 2025/2026 scam patterns.");
    });

    const cryptoIntent = inspectCryptoInvestmentScamIntent(target, messageContext);
    if (cryptoIntent.active) {
      score -= cryptoIntent.weight;
      const evidenceBits = [];
      if (cryptoIntent.seedPhrasePattern) evidenceBits.push("seed/private-key recovery wording");
      if (cryptoIntent.walletConnectPattern) evidenceBits.push("wallet connect/restore wording");
      if (cryptoIntent.guaranteedReturnPattern) evidenceBits.push("guaranteed-return/profit wording");
      if (cryptoIntent.recoveryFeePattern) evidenceBits.push("recovery/unlock fee wording");
      if (cryptoIntent.tradingBotPattern) evidenceBits.push("trading-bot/signal/investment group wording");
      if (cryptoIntent.intent.length) evidenceBits.push("crypto/investment words: " + cryptoIntent.intent.slice(0,5).join(", "));
      if (cryptoIntent.money.length) evidenceBits.push("money/wallet words: " + cryptoIntent.money.slice(0,4).join(", "));
      if (cryptoIntent.sensitive.length) evidenceBits.push("sensitive wallet words: " + cryptoIntent.sensitive.slice(0,4).join(", "));
      addSignal(signals, cryptoIntent.severity, "Crypto / investment scam pattern", "The message or target combines crypto, wallet, exchange, investment, profit, recovery, trading-bot, seed phrase, private-key, or guaranteed-return language with action, pressure, sensitive access, money, or mismatch context. Evidence: " + (evidenceBits.join("; ") || "crypto/investment density " + cryptoIntent.density) + ". Do not share seed phrases or private keys, and verify investment or wallet claims through official, typed channels before sending funds.", cryptoIntent.weight);
      technical.push("v2.85 crypto/investment scam classifier: URL/message lane checked for wallet, seed phrase, fake profit, recovery-fee, exchange, and trading-bot lures.");
      timeline.push("v2.85 checked whether the target was trying to move the user into a crypto, wallet, investment, recovery, or guaranteed-return scam flow.");
    }

    const romanceIntent = inspectRomanceTrustScamIntent(target, messageContext);
    if (romanceIntent.active) {
      score -= romanceIntent.weight;
      const evidenceBits = [];
      if (romanceIntent.moveOffPlatformPattern) evidenceBits.push("move-off-platform wording");
      if (romanceIntent.emergencyMoneyPattern) evidenceBits.push("emergency-money or travel-fee wording");
      if (romanceIntent.loveTrustPattern) evidenceBits.push("relationship/trust plus money wording");
      if (romanceIntent.privateLeveragePattern) evidenceBits.push("private-photo or leverage wording");
      if (romanceIntent.fakePersonaPattern) evidenceBits.push("fake-persona emergency wording");
      if (romanceIntent.intent.length) evidenceBits.push("trust-building words: " + romanceIntent.intent.slice(0,5).join(", "));
      if (romanceIntent.money.length) evidenceBits.push("money/gift-card words: " + romanceIntent.money.slice(0,4).join(", "));
      if (romanceIntent.sensitive.length) evidenceBits.push("sensitive/private words: " + romanceIntent.sensitive.slice(0,4).join(", "));
      addSignal(signals, romanceIntent.severity, "Romance / trust-building social engineering pattern", "The message or target combines relationship, friendship, private-chat, move-off-platform, emergency, gift-card, travel-fee, or emotional trust-building language with money, pressure, sensitive information, or private-photo leverage. Evidence: " + (evidenceBits.join("; ") || "trust-building density " + romanceIntent.density) + ". Do not send money, gift cards, crypto, private photos, or identity details to someone you have not independently verified.", romanceIntent.weight);
      technical.push("v2.86 romance/trust-building classifier: URL/message lane checked for emotional trust-building, move-off-platform, emergency-money, gift-card, and private-photo leverage lures.");
      timeline.push("v2.86 checked whether the target was trying to move the user into a romance, friendship, emergency-money, private-chat, or trust-building scam flow.");
    }


    const mfaOtpIntent = inspectMfaOtpCodeTheft(target, messageContext);
    if (mfaOtpIntent.active) {
      score -= mfaOtpIntent.weight;
      const evidenceBits = [];
      if (mfaOtpIntent.codeHarvestPattern) evidenceBits.push("one-time code sharing wording");
      if (mfaOtpIntent.pushApprovalPattern) evidenceBits.push("push/login approval wording");
      if (mfaOtpIntent.recoveryCodePattern) evidenceBits.push("backup/recovery code wording");
      if (mfaOtpIntent.intent.length) evidenceBits.push("code words: " + mfaOtpIntent.intent.slice(0,5).join(", "));
      if (mfaOtpIntent.actions.length) evidenceBits.push("action words: " + mfaOtpIntent.actions.slice(0,4).join(", "));
      if (mfaOtpIntent.context.length) evidenceBits.push("account/security context: " + mfaOtpIntent.context.slice(0,4).join(", "));
      addSignal(signals, mfaOtpIntent.severity, "MFA / OTP code theft pattern", "The message or target combines one-time code, two-factor, authenticator, login approval, push approval, backup-code, or recovery-code language with action, pressure, sensitive account context, or mismatch clues. Evidence: " + (evidenceBits.join("; ") || "MFA/OTP density " + mfaOtpIntent.density) + ". Never share one-time codes or approve login prompts unless you personally initiated the login through a known official route.", mfaOtpIntent.weight);
      technical.push("v2.99 MFA/OTP code theft classifier: URL/message lane checked for one-time-code, authenticator, approval-prompt, and recovery-code lures.");
      timeline.push("v2.99 checked whether the target was trying to steal or trigger an MFA, OTP, authenticator, or login approval action.");
    }
    const accountRecoveryIntent = inspectAccountRecoveryTakeover(target, messageContext);
    if (accountRecoveryIntent.active) {
      score -= accountRecoveryIntent.weight;
      const evidenceBits = [];
      if (accountRecoveryIntent.passwordResetPattern) evidenceBits.push("password reset/account recovery wording");
      if (accountRecoveryIntent.recoveryLinkPattern) evidenceBits.push("recovery link/unlock wording");
      if (accountRecoveryIntent.changeAlertPattern) evidenceBits.push("account/device change alert wording");
      if (accountRecoveryIntent.intent.length) evidenceBits.push("recovery words: " + accountRecoveryIntent.intent.slice(0,5).join(", "));
      if (accountRecoveryIntent.actions.length) evidenceBits.push("action words: " + accountRecoveryIntent.actions.slice(0,4).join(", "));
      if (accountRecoveryIntent.context.length) evidenceBits.push("account/security context: " + accountRecoveryIntent.context.slice(0,4).join(", "));
      addSignal(signals, accountRecoveryIntent.severity, "Account Recovery / Password Reset Takeover pattern", "The message or target combines password-reset, account-recovery, account-unlock, reactivation, email/phone/device-change, session-reset, or recovery-link language with action, pressure, sensitive account context, or mismatch clues. Evidence: " + (evidenceBits.join("; ") || "account recovery density " + accountRecoveryIntent.density) + ". Do not use recovery or reset links from unexpected messages; go directly to the official app or typed website.", accountRecoveryIntent.weight);
      technical.push("v3.00 account recovery/password reset takeover classifier: URL/message lane checked for password-reset, account-recovery, unlock/reactivation, device-change, and recovery-link lures.");
      timeline.push("v3.00 checked whether the target was trying to move the user into an account recovery or password reset takeover flow.");
    }
    const urgencyIntent = inspectUrgencyPressureTactic(target, messageContext);
    if (urgencyIntent.active) {
      score -= urgencyIntent.weight;
      const evidenceBits = [];
      if (urgencyIntent.countdownPattern) evidenceBits.push("deadline/countdown wording");
      if (urgencyIntent.fearPressurePattern) evidenceBits.push("fear/final-notice pressure");
      if (urgencyIntent.actionNowPattern) evidenceBits.push("act-now wording");
      if (urgencyIntent.pressure.length) evidenceBits.push("pressure words: " + urgencyIntent.pressure.slice(0,5).join(", "));
      if (urgencyIntent.actions.length) evidenceBits.push("action words: " + urgencyIntent.actions.slice(0,4).join(", "));
      if (urgencyIntent.sensitive.length) evidenceBits.push("sensitive context: " + urgencyIntent.sensitive.slice(0,4).join(", "));
      addSignal(signals, urgencyIntent.severity, "Urgency / pressure tactic pattern", "The message or target combines countdown, final-notice, act-now, penalty, suspension, or fear-pressure language with action or sensitive context. Evidence: " + (evidenceBits.join("; ") || "urgency density " + urgencyIntent.density) + ". Slow down and verify through a separate trusted route before clicking, calling, paying, or entering information.", urgencyIntent.weight);
      technical.push("v2.97 urgency/pressure classifier: URL/message lane checked for countdown, final-notice, act-now, and fear-pressure scam tactics.");
      timeline.push("v2.97 checked whether the target was using urgency or fear to push fast action.");
    }
    const authorityIntent = inspectAuthorityImpersonationVoice(target, messageContext);
    if (authorityIntent.active) {
      score -= authorityIntent.weight;
      const evidenceBits = [];
      if (authorityIntent.officialNoticePattern) evidenceBits.push("official notice/case reference wording");
      if (authorityIntent.departmentPersonaPattern) evidenceBits.push("department/team persona wording");
      if (authorityIntent.authorityPlusActionPattern) evidenceBits.push("authority plus action wording");
      if (authorityIntent.identities.length) evidenceBits.push("identity words: " + authorityIntent.identities.slice(0,4).join(", "));
      if (authorityIntent.claims.length) evidenceBits.push("claim words: " + authorityIntent.claims.slice(0,4).join(", "));
      if (authorityIntent.sensitive.length) evidenceBits.push("sensitive context: " + authorityIntent.sensitive.slice(0,4).join(", "));
      addSignal(signals, authorityIntent.severity, "Authority / impersonation voice pattern", "The message or target combines official-sounding department, case, reference, compliance, review, or support-team language with action, pressure, sensitive context, or brand mismatch. Evidence: " + (evidenceBits.join("; ") || "authority density " + authorityIntent.density) + ". Verify through a known channel instead of trusting the claimed authority inside the message.", authorityIntent.weight);
      technical.push("v2.98 authority/impersonation voice classifier: URL/message lane checked for official notice, department persona, case/reference, compliance, and review tactics.");
      timeline.push("v2.98 checked whether the target was borrowing authority language to pressure action.");
    }

    if (target.markdownLabel) {
      const visibleHints = findTrustedHintsInVisibleText(target.markdownLabel);
      const mismatchedHints = visibleHints.filter(hit => !bankFamily && !isTrusted);
      if (mismatchedHints.length) {
        const readable = mismatchedHints.slice(0,3).map(hit => hit.family + " via '" + hit.hint + "'").join(", ");
        score -= 24;
        addSignal(signals,"high","Visible label / real destination mismatch","The visible markdown label mentions a trusted brand or root (" + readable + "), but the actual link destination resolves to " + root + ". Judge the destination inside parentheses, not the clickable words.",24);
        timeline.push("Visible-link text was compared against the real destination; Proxuma found a brand mismatch.");
      } else if (visibleHints.length) {
        addSignal(signals,"low","Visible label matches known family","The visible markdown label references a known family and the destination root appears consistent with that family. Proxuma still judges the real destination first.",-2);
        technical.push("Markdown visible-label check: known-family wording did not mismatch the destination root.");
      } else {
        technical.push("Markdown visible-label check: no trusted-brand claim found in visible text.");
      }
    }

    if (target.scheme !== "https") { score -= 14; addSignal(signals,"medium","No clear HTTPS","The submitted target does not clearly begin with HTTPS. That lowers confidence for sensitive actions.",14); }
    else { technical.push("HTTPS scheme detected in submitted target."); }
    if (target.normalizationNotes && target.normalizationNotes.some(note => /Protocol-relative/i.test(note))) {
      addSignal(signals,"medium","Protocol-relative link","The input began with // instead of a full scheme. Proxuma normalized it before scoring because this style can hide the destination when copied out of context.",8);
      technical.push("Protocol-relative normalization: applied.");
    }

    if (hasParserControlCharacters(target.sourceRaw || target.raw)) {
      score -= 24;
      addSignal(signals,"high","Parser control character","The raw input contains encoded or literal control characters such as null, tab, or line-break bytes. These can confuse parsers, logs, or display boundaries.",24);
      timeline.push("Parser-control characters found before normal trust decisions were applied.");
    }

    if (hasDoubleEncodedSeparator(target.sourceRaw || target.raw)) {
      score -= 18;
      addSignal(signals,"medium","Double-encoded separator","The raw input appears to hide separators like dot, slash, colon, backslash, or @ behind a second layer of percent encoding. This can conceal the true boundary until later decoding.",18);
      technical.push("Double-encoded separator check: triggered.");
    }

    if (isPrivateOrLocalHost(host)) {
      score -= 28;
      addSignal(signals,"high","Private or local-network destination","The target points at localhost, a private IP range, or an internal-style host. That may be normal for admin tools, but it is unsafe to trust from unsolicited QR codes or messages.",28);
      timeline.push("Private/local destination detected; Proxuma treated it as high-risk outside a known safe context.");
    }


    if (hasMalformedDomainPunctuation(target)) {
      score -= 18;
      addSignal(signals,"medium","Malformed domain punctuation","The visible destination contains punctuation or structure that does not belong inside a normal web domain, such as a comma in place of a dot. Re-type the address or verify it through a trusted source before using it.",18);
      technical.push("Malformed domain punctuation check: triggered.");
      timeline.push("Malformed host punctuation found; Proxuma moved the result into review instead of treating it as clean.");
    } else {
      technical.push("Malformed domain punctuation check: clear.");
    }

    const domainEndingSpoof = inspectDomainEndingSpoof(target);
    if (domainEndingSpoof.active) {
      score -= domainEndingSpoof.weight;
      addSignal(signals, domainEndingSpoof.severity, domainEndingSpoof.title, domainEndingSpoof.detail, domainEndingSpoof.weight);
      technical.push("v3.24.1 domain-ending spoof check: " + domainEndingSpoof.kind + " detected.");
      timeline.push("v3.24.1 checked dot-com lookalike endings and comma-domain punctuation before final scoring.");
    } else {
      technical.push("v3.24.1 domain-ending spoof check: clear.");
    }

    if (target.username) {
      score -= 22;
      addSignal(signals,"high","Username-in-link deception","The URL contains text before an @ symbol. Attackers can use this to make the left side look trusted while the browser goes to the host after @.",22);
      timeline.push("User-info section detected before the real host; the true destination still resolves to " + root + ".");
    }

    if (target.port && !["80","443"].includes(target.port)) {
      score -= 10;
      addSignal(signals,"medium","Unusual network port","The URL specifies port " + target.port + ", which is uncommon for normal public login or banking pages.",10);
    }

    const redirectRootsEarly = findRedirectDestinationRoots(target);
    if (/(redirect|return|continue|url|target|next)=https?%3a%2f%2f/i.test(target.raw) || /(redirect|return|continue|url|target|next)=https?:\/\//i.test(target.raw)) {
      const sameRootRedirect = redirectRootsEarly.length && redirectRootsEarly.every(item => item.root === root);
      if (sameRootRedirect && (isTrusted || bankFamily)) {
        addSignal(signals,"low","Same-root redirect on known root","A redirect-style parameter points back to the same trusted root. Proxuma notes it, but v2.46 calibration avoids over-punishing normal first-party navigation.",-2);
        technical.push("Embedded redirect target: same-root known-family relief applied.");
      } else {
        score -= 18;
        addSignal(signals,"medium","Embedded redirect target","The URL appears to carry another web address inside a parameter. That can be legitimate, but it is also a common redirect trick.",18);
        timeline.push("Embedded destination parameter found; user should verify where the link forwards before trusting it.");
      }
    }

    const queryFindings = inspectQueryParams(target);
    if (queryFindings.redirect.length) {
      const sameRootRedirect = redirectRootsEarly.length && redirectRootsEarly.every(item => item.root === root);
      if (sameRootRedirect && (isTrusted || bankFamily)) {
        addSignal(signals,"low","First-party redirect parameter","Redirect-style parameter found, but it points back to the same known root. Proxuma notes it without treating it like a cross-site handoff.",-2);
        technical.push("Redirect parameter found: same-root known-family relief applied.");
      } else {
        const weight = Math.min(24, 16 + ((queryFindings.redirect.length - 1) * 4));
        score -= weight;
        addSignal(signals,"medium","Redirect parameter found","A redirect-style parameter appears to contain another destination: " + queryFindings.redirect.slice(0,4).join(", ") + ". This can be normal for large sites, but it is a common handoff trick in phishing chains.",weight);
        timeline.push("Redirect-style query parameter found; Proxuma marked it for verification before trust.");
      }
    }
    const redirectRoots = redirectRootsEarly.length ? redirectRootsEarly : findRedirectDestinationRoots(target);
    const crossRootRedirects = redirectRoots.filter(item => item.root && item.root !== root);
    if (crossRootRedirects.length) {
      const readable = crossRootRedirects.slice(0,3).map(item => item.param + "→" + item.root).join(", ");
      const trustedDestination = crossRootRedirects.some(item => trustedRoots.has(item.root) || matchingTrustedFamily(item.root));
      const untrustedSensitiveRedirect = crossRootRedirects.some(item => {
        const embeddedText = ((item.host || "") + " " + (item.path || "") + " " + safeDecodeForInspection(item.path || "")).toLowerCase();
        const embeddedTrusted = trustedRoots.has(item.root) || !!matchingTrustedFamily(item.root);
        return !embeddedTrusted && Array.from(highValueWorkflowWords).some(word => embeddedText.includes(word));
      });
      const weight = untrustedSensitiveRedirect && (isTrusted || bankFamily) ? 28 : (trustedDestination && !(isTrusted || bankFamily) ? 22 : 14);
      score -= weight;
      addSignal(signals, untrustedSensitiveRedirect && (isTrusted || bankFamily) ? "high" : (trustedDestination && !(isTrusted || bankFamily) ? "high" : "medium"), untrustedSensitiveRedirect && (isTrusted || bankFamily) ? "Trusted-root redirect to sensitive external destination" : "Cross-root redirect chain", "A redirect parameter points to a different root domain: " + readable + ". Judge the starting root first, then the hidden destination in the parameter.", weight);
      if (untrustedSensitiveRedirect && (isTrusted || bankFamily)) technical.push("v2.56: trusted-root open redirect to a sensitive external target escalated for phishing-chain review.");
      timeline.push("Cross-root redirect chain found and compared against the starting domain.");
    }

    const redirectIntent = classifyRedirectIntent(target, messageContext, redirectRoots, queryFindings);
    if (redirectIntent.active) {
      score -= redirectIntent.weight;
      addSignal(signals, redirectIntent.severity, redirectIntent.title, redirectIntent.detail, redirectIntent.weight);
      technical.push("v2.67 redirect intent classifier: " + redirectIntent.mode + ".");
      timeline.push("v2.67 classified redirect intent before final advice.");
    }
    if (queryFindings.credential.length && !(isTrusted || bankFamily)) {
      const weight = Math.min(26, 14 + ((queryFindings.credential.length - 1) * 4));
      score -= weight;
      addSignal(signals,"medium","Credential-like query parameter","The URL carries login, token, session, code, or account-style parameter names on a non-trusted root: " + queryFindings.credential.slice(0,5).join(", ") + ". Do not submit private information until verified.",weight);
      timeline.push("Credential-style parameter names appeared outside a known trusted root.");
    } else if (queryFindings.credential.length) {
      addSignal(signals,"low","Credential parameter on known root","Login/session-style parameter names appeared, but the root matches a known local family. Context still matters.",-2);
    }
    if (queryFindings.count >= 8 || queryFindings.longValueCount >= 2) {
      score -= 8;
      addSignal(signals,"medium","Dense query string","The URL carries many parameters or multiple very long values, which can hide tracking, redirects, or state tokens.",8);
    }

    if (hasEncodedAtOrSlashTrick(target.raw)) {
      const sameRootRedirect = redirectRootsEarly.length && redirectRootsEarly.every(item => item.root === root);
      if (sameRootRedirect && (isTrusted || bankFamily) && !/%40|%5c|\\/i.test(target.raw)) {
        addSignal(signals,"low","Encoded same-root redirect separators","Encoded slashes were found inside a same-root redirect parameter on a known root. Proxuma records the encoding without escalating it as deception.",-1);
        technical.push("Encoded separator trick: same-root known-family relief applied.");
      } else {
        score -= 12;
        addSignal(signals,"medium","Encoded separator trick","The raw input contains encoded @, encoded //, or backslash separators. These can make the visible link harder to read than the browser's final interpretation.",12);
        timeline.push("Encoded separator characters were found in the raw target.");
      }
    }

    if (hasAuthorityConfusion(target.raw) && !target.username) {
      score -= 18;
      addSignal(signals,"high","Authority boundary confusion","The raw input uses @, encoded @, or backslash-style authority confusion without a clean normal username field. This can make one domain appear visible while another destination controls the navigation.",18);
      timeline.push("Authority-boundary confusion was found in the raw target and escalated as a safety hardening rule.");
    }

    if (findDoubleExtension(path)) {
      score -= 30;
      addSignal(signals,"high","Double-extension download disguise","The path looks like a harmless file name followed by a risky executable-style extension. Treat this as a strong download warning.",30);
      timeline.push("Double-extension pattern found; Proxuma escalated the download risk.");
    }

    if (isIp(host)) { score -= 26; addSignal(signals,"high","IP address destination","The link points to an IP address instead of a readable domain. That makes ownership and trust harder to judge.",26); }
    const shortenerRoot = isKnownShortenerRoot(root);
    const relayWrapper = isRelayWrapperTarget(target);
    if (shortenerRoot) {
      const sensitiveContext = hasSensitiveBrandContext(messageContext);
      score -= sensitiveContext ? 28 : 18;
      addSignal(signals, sensitiveContext ? "high" : "medium", sensitiveContext ? "Brand message uses shortened link" : "Shortener detected", sensitiveContext ? "The message uses trusted-brand or pressure wording but sends the user through a shortened link. Offline Proxuma cannot see the final destination without permission, so treat sensitive actions as unsafe." : "Short links hide the final destination. Offline Proxuma can warn about the concealment, but should ask permission before any future online expansion.", sensitiveContext ? 28 : 18);
      technical.push("v2.57 shortener intelligence: recognized known short-link root " + root + ".");
      trust.push("Shortener boundary: final destination was not expanded because this build remains offline-first.");
      timeline.push("v2.57 identified a shortened link and preserved privacy by not making an external expansion request.");
    }
    if (relayWrapper) {
      const sensitiveContext = hasSensitiveBrandContext(messageContext);
      score -= sensitiveContext ? 24 : 12;
      addSignal(signals, sensitiveContext ? "high" : "medium", sensitiveContext ? "Sensitive message uses relay wrapper" : "Relay / tracking wrapper", sensitiveContext ? "The message combines brand or pressure wording with a redirect/relay wrapper. Verify the final destination before clicking or entering information." : "This link appears to pass through a redirect, tracking, or relay wrapper. The visible domain may not be the final destination.", sensitiveContext ? 24 : 12);
      technical.push("v2.57 relay intelligence: wrapper/root pattern detected for " + host + ".");
      timeline.push("v2.57 classified the target as a relay/tracking wrapper before final judgment.");
    }
    if (subdomainDepth >= 3) { score -= 18; addSignal(signals,"medium","Heavy subdomain stack","Many subdomain layers can push the real root domain out of sight.",18); }
    else if (subdomainDepth >= 2) { score -= 10; addSignal(signals,"medium","Extra subdomain layers","Extra labels before the root domain deserve a closer look.",10); }

    const hyphenCount = (host.match(/-/g) || []).length;
    if (hyphenCount >= 3) { score -= 14; addSignal(signals,"medium","Heavy hyphen use","Multiple hyphens often appear in imitation or disposable domains.",14); }
    else if (hyphenCount >= 1 && brands.length) { score -= 8; addSignal(signals,"medium","Brand plus hyphen pattern","A brand-like word combined with hyphens should be checked against the real root domain.",8); }

    if (/%[0-9a-f]{2}/i.test(target.raw) || /%[0-9a-f]{2}/i.test(path)) {
      const sameRootRedirect = redirectRootsEarly.length && redirectRootsEarly.every(item => item.root === root);
      if (sameRootRedirect && (isTrusted || bankFamily) && !/%40|%5c|%00|%0d|%0a|%09/i.test(target.raw)) {
        addSignal(signals,"low","Encoded first-party URL value","Encoded characters appear in a same-root parameter on a known root. Proxuma records this as normal URL encoding unless stronger deception appears.",-1);
      } else {
        score -= 12;
        addSignal(signals,"medium","Encoded characters","Encoded characters can hide spaces, redirects, or payload details inside the URL.",12);
      }
    }
    if (/xn--/i.test(host) || unicodeLookalikes.test(host)) { score -= 28; addSignal(signals,"high","Unicode / punycode lookalike risk","The hostname contains characters that can imitate normal letters. Treat this as a strong warning.",28); }

    const urlIntel = inspectUrlIntelligenceExpansion(target);
    const trustedStructureRelief = !!(isTrusted || bankFamily);
    if (urlIntel.length >= 320) {
      const weight = trustedStructureRelief ? 4 : 12;
      score -= weight;
      addSignal(signals, trustedStructureRelief ? "low" : "medium", "Very long URL structure", "The URL is " + urlIntel.length + " characters long. Long links can bury the meaningful destination or carry opaque state. QANTRAE weighs this lightly on known roots and more strongly when the root is unfamiliar.", weight);
    } else if (urlIntel.length >= 200) {
      const weight = trustedStructureRelief ? 2 : 7;
      score -= weight;
      addSignal(signals, trustedStructureRelief ? "low" : "medium", "Long URL structure", "The URL is " + urlIntel.length + " characters long. Length alone is not malicious, but it can make the true destination harder to inspect.", weight);
    }
    if (urlIntel.numericHostLabel && !isIp(host) && !trustedStructureRelief) {
      score -= 10;
      addSignal(signals,"medium","Numeric host-label deception","A hostname label is unusually numeric without being a normal IP address. Numeric labels can be legitimate, but they can also make a destination harder to recognize at a glance.",10);
    }
    if (urlIntel.pathDepth >= 8 && !trustedStructureRelief) {
      score -= 8;
      addSignal(signals,"medium","Deep path nesting","The URL contains " + urlIntel.pathDepth + " path layers. Deep nesting can hide phishing-kit folders or push meaningful names out of view.",8);
    }
    if (urlIntel.percentCount >= 10 && !trustedStructureRelief) {
      score -= 8;
      addSignal(signals,"medium","Heavy URL encoding density","The URL contains " + urlIntel.percentCount + " percent-encoded byte sequences. Heavy encoding can conceal separators, destinations, or payload details.",8);
    }
    if (urlIntel.nestedEncoding && !trustedStructureRelief) {
      score -= 16;
      addSignal(signals,"medium","Nested URL encoding","QANTRAE found evidence that important URL separators may be hidden behind more than one decoding layer. Multi-layer encoding is a stronger concealment clue than ordinary percent encoding.",16);
      timeline.push("v3.55 URL intelligence detected nested encoding before final scoring.");
    }
    if (urlIntel.nestedUrlValue && crossRootRedirects.length === 0 && !trustedStructureRelief) {
      score -= 12;
      addSignal(signals,"medium","Nested destination-like value","A URL-shaped destination appears inside the path or query even though it was not classified as a normal redirect parameter. Verify which domain ultimately controls the navigation.",12);
    }
    if (urlIntel.longOpaqueValue && !trustedStructureRelief) {
      score -= 7;
      addSignal(signals,"medium","Opaque query payload","A query value is unusually long and machine-like. This may be a normal token, but on an unfamiliar root it reduces human readability and can conceal state or redirect information.",7);
    }
    if (urlIntel.authBaitDensity >= 4 && !trustedStructureRelief && !(brands.length || credentialIntent.active)) {
      score -= 10;
      addSignal(signals,"medium","Dense account-access wording","Several login, verification, password, recovery, or payment terms are packed into the URL structure on an unfamiliar root. Dense account-access wording deserves verification even when no single token is decisive.",10);
    }

    const randomizedRoot = findRandomizedRootPattern(root);
    if (randomizedRoot && !(isTrusted || bankFamily)) {
      const hasWorkflowContext = Array.from(highValueWorkflowWords).some(word => allText.includes(word));
      const weight = hasWorkflowContext ? 18 : 10;
      score -= weight;
      addSignal(signals, hasWorkflowContext ? "medium" : "low", "Random-looking root pattern", "The root label looks machine-generated or unusually random: " + randomizedRoot.label + " (entropy " + randomizedRoot.entropy + "). This is not proof by itself, but it raises caution when paired with login, payment, or security wording.", weight);
      timeline.push("Randomized-root pattern checked; Proxuma treated it as supporting evidence rather than an automatic block.");
    }

    const suspiciousPathKit = findSuspiciousPathKit(path);
    if (suspiciousPathKit && !(isTrusted || bankFamily)) {
      const weight = Math.min(24, 16 + suspiciousPathKit.folderHits.length * 2);
      score -= weight;
      addSignal(signals,"medium","Phishing-kit path pattern","The path combines deep folders with login/account/security-style file or folder names: " + suspiciousPathKit.folderHits.join(", ") + (suspiciousPathKit.fileHit ? ", " + suspiciousPathKit.fileHit : "") + ". This resembles a hosted phishing-kit layout more than a normal landing page.",weight);
      timeline.push("Phishing-kit style path depth and folder names found on a non-trusted root.");
    }

    const redirectMismatches = findTrustedBrandRedirectMismatch(target, root);
    if (redirectMismatches.length && !(isTrusted || bankFamily)) {
      const readableHits = redirectMismatches.slice(0,3).map(hit => hit.param + "→" + hit.embeddedRoot + " (" + hit.family + ")").join(", ");
      const weight = Math.min(24, 16 + ((redirectMismatches.length - 1) * 4));
      score -= weight;
      addSignal(signals,"medium","Trusted-brand redirect mismatch","A non-trusted root carries a redirect parameter pointing toward a known institution family: " + readableHits + ". This can be a handoff trick; verify the starting domain, not just the embedded destination.",weight);
      timeline.push("Redirect mismatch found: trusted destination language appeared inside an untrusted starting domain.");
    }

    const pathEmbeds = findEmbeddedTrustedDomainInPath(host, path, root);
    if (pathEmbeds.length && !(isTrusted || bankFamily)) {
      const readableHits = pathEmbeds.slice(0,3).map(hit => hit.officialRoot + " (" + hit.family + ")").join(", ");
      score -= 24;
      addSignal(signals,"high","Trusted domain embedded in path","The path contains a known trusted domain even though the real root is different: " + readableHits + ". Attackers can place official-looking domains after the slash to distract from the true destination.",24);
      timeline.push("Trusted-domain-in-path deception found; Proxuma emphasized the real root over the visible path text.");
    }

    const stuffedSubdomains = findTrustedRootStuffedSubdomain(host, root);
    if (stuffedSubdomains.length && !(isTrusted || bankFamily)) {
      const readableHits = stuffedSubdomains.slice(0,3).map(hit => hit.officialRoot + " (" + hit.family + ")").join(", ");
      score -= 24;
      addSignal(signals,"high","Trusted root stuffed into subdomain","The hostname places a known trusted root before the real domain: " + readableHits + ". The actual controlling root remains " + root + ".",24);
      timeline.push("Trusted-root-stuffed subdomain found; Proxuma separated the fake front from the real root.");
    }

    const foundPressure = includesAny(allText, pressureWords);
    if (foundPressure.length) {
      if ((isTrusted || bankFamily) && !messageContext.mismatchedBrands.length) {
        const reliefWeight = foundPressure.length > 2 ? -3 : -2;
        addSignal(signals, "low", "Trusted workflow wording", "Found action/workflow terms on a known local root: " + foundPressure.slice(0,6).join(", ") + ". v2.90 records these as normal service context unless stronger deception appears.", reliefWeight);
        technical.push("v2.90 safe/trusted context relief: pressure/workflow wording on a known root was not penalized by itself.");
      } else {
        const weight = Math.min(28, foundPressure.length * 6);
        score -= weight;
        addSignal(signals, foundPressure.length > 2 ? "high" : "medium", "Pressure wording", "Found terms: " + foundPressure.slice(0,6).join(", ") + ".", weight);
      }
    }

    const workflowHits = findSensitiveWorkflowDensity(host, path);
    if (workflowHits.length >= 3 && !(isTrusted || bankFamily) && !brands.length) {
      const weight = Math.min(22, 10 + ((workflowHits.length - 3) * 4));
      score -= weight;
      addSignal(signals,"medium","Sensitive workflow cluster","The target combines several login, account, payment, security, or verification words on an untrusted root: " + workflowHits.slice(0,6).join(", ") + ".",weight);
      timeline.push("Sensitive workflow words clustered outside a trusted root.");
    }

    const lookalikeSecurityWords = findLookalikeSecurityWords(allText);
    if (lookalikeSecurityWords.length) {
      const readableHits = lookalikeSecurityWords.slice(0,4).map(hit => hit.token + " → " + hit.normalized).join(", ");
      const weight = Math.min(28, 20 + ((lookalikeSecurityWords.length - 1) * 4));
      score -= weight;
      addSignal(signals,"medium","Lookalike security word","A number or symbol appears inside a sensitive word: " + readableHits + ". This can be used to disguise words like login, secure, verify, account, or password.",weight);
      timeline.push("Lookalike security-word pattern found; Proxuma treated it as caution evidence, not an automatic high-risk verdict.");
    }

    const lookalikeInstitutionDomains = findLookalikeInstitutionDomains(host, path, root);
    if (lookalikeInstitutionDomains.length && !bankFamily) {
      const readableHits = lookalikeInstitutionDomains.slice(0,4).map(hit => hit.observed + " → " + hit.normalized + " (" + hit.family + ")").join(", ");
      const weight = Math.min(34, 26 + ((lookalikeInstitutionDomains.length - 1) * 4));
      score -= weight;
      addSignal(signals,"high","Lookalike institution domain","The root or hostname appears to use number/symbol substitutions to imitate a known institution: " + readableHits + ". Verify by typing the official address yourself instead of using this link.",weight);
      timeline.push("Lookalike institution-domain pattern found; Proxuma treated it as stronger evidence than a generic suspicious word.");
    }

    const nearMissInstitutionRoots = (!bankFamily && !lookalikeInstitutionDomains.length) ? findNearMissInstitutionRoot(root) : [];
    if (nearMissInstitutionRoots.length) {
      const readableHits = nearMissInstitutionRoots.slice(0,3).map(hit => hit.observed + " ≈ " + hit.expected + " (" + hit.family + ")").join(", ");
      const hasWorkflowContext = Array.from(highValueWorkflowWords).some(word => allText.includes(word));
      const weight = hasWorkflowContext ? 30 : 18;
      score -= weight;
      addSignal(signals, hasWorkflowContext ? "high" : "medium", "Near-miss institution root", "The root domain is very close to a known institution spelling: " + readableHits + ". Near-miss domains are common in impersonation attempts.", weight);
      timeline.push("Near-miss institution spelling found; Proxuma checked whether security/account wording made the pattern more serious.");
    }

    const shortInstitutionPressureDomains = (!bankFamily && !lookalikeInstitutionDomains.length) ? findShortInstitutionPressureDomains(host, path, root) : [];
    if (shortInstitutionPressureDomains.length) {
      const readableHits = shortInstitutionPressureDomains.slice(0,4).map(hit => hit.observed + " → " + hit.normalized + " (" + hit.family + ")").join(", ");
      const weight = Math.min(30, 22 + ((shortInstitutionPressureDomains.length - 1) * 4));
      score -= weight;
      addSignal(signals,"high","Short institution alias with security wording","A short institution name appears embedded inside a domain token near security/login language: " + readableHits + ". Short names are handled carefully to avoid accidental matches, but this pattern deserves strong caution.",weight);
      timeline.push("Short institution alias plus security wording found; Proxuma treated it as institution-impersonation evidence, while keeping boundary controls for ordinary words.");
    }

    const downloadTrap = inspectDownloadTrap(target);
    if (downloadTrap.doubleExtension) {
      score -= 30;
      addSignal(signals,"high","Double-extension download trap", "The link appears to combine a harmless-looking document/image name with an executable-style extension. Treat it as unsafe unless verified through the official source.",30);
      timeline.push("v2.61 found a double-extension download trap pattern.");
    }
    if (downloadTrap.executable.length || downloadTrap.paramExecutable.length) {
      const hits = Array.from(new Set(downloadTrap.executable.concat(downloadTrap.paramExecutable))).slice(0,6).join(", ");
      score -= 30;
      addSignal(signals,"high","Executable download reference", "The URL references an executable, installer, script, or app package signal: " + hits + ". Do not download or run files from unsolicited links or QR payloads.",30);
      timeline.push("v2.61 executable/download-trap intelligence found direct executable or installer evidence.");
    }
    if ((downloadTrap.archive.length || downloadTrap.paramArchive.length) && !(downloadTrap.executable.length || downloadTrap.paramExecutable.length)) {
      const hits = Array.from(new Set(downloadTrap.archive.concat(downloadTrap.paramArchive))).slice(0,6).join(", ");
      const sensitiveContext = findSensitiveWorkflowDensity(host, path).length >= 1 || Array.from(highValueWorkflowWords).some(word => allText.includes(word));
      const weight = sensitiveContext ? 22 : 14;
      score -= weight;
      addSignal(signals, sensitiveContext ? "high" : "medium", "Compressed file delivery", "The link references a compressed/downloadable archive type: " + hits + ". Archives can hide executable contents, especially when paired with invoice, update, banking, or verification language.", weight);
      timeline.push("v2.61 archive-delivery intelligence reviewed compressed file risk.");
    }
    if (downloadTrap.downloadWords.length >= 2 && !(downloadTrap.executable.length || downloadTrap.paramExecutable.length || downloadTrap.archive.length || downloadTrap.paramArchive.length)) {
      const hits = downloadTrap.downloadWords.slice(0,6).join(", ");
      score -= 10;
      addSignal(signals,"medium","Download/installer wording", "The URL uses download or installer-style wording: " + hits + ". This is not proof of malware, but it deserves caution before opening from a QR code or message.",10);
      timeline.push("v2.61 found download/installer wording without a direct file extension.");
    }
    if (downloadTrap.paramDownloadWords.length && !(downloadTrap.paramExecutable.length || downloadTrap.paramArchive.length)) {
      const benignTrustedDownloadParam = (isTrusted || bankFamily) && !downloadTrap.executable.length && !downloadTrap.archive.length && !messageContext.mismatchedBrands.length && !messageContext.pressure.length;
      if (benignTrustedDownloadParam) {
        addSignal(signals,"low","Trusted download parameter", "A download-style parameter appears on a known root. Proxuma records it as file-delivery context without escalating unless executable, archive, pressure, or mismatch evidence appears.",-1);
        technical.push("v3.04 false-positive tuning: trusted download-style parameter relief applied.");
      } else {
        score -= 8;
        addSignal(signals,"medium","Download-style parameter", "The URL uses parameter names associated with files or downloads: " + downloadTrap.paramDownloadWords.slice(0,5).join(", ") + ". Review the source before opening or saving anything.",8);
      }
    }

    const foundExt = riskyExtensions.filter(ext => path.includes(ext));
    if (foundExt.length && !downloadTrap.executable.length) { score -= 28; addSignal(signals,"high","Risky file download", "Path references a potentially executable or high-risk file type: " + foundExt.join(", ") + ".",28); }
    const tld = tldOf(root);
    if (riskyTlds.has(tld)) { score -= 14; addSignal(signals,"medium","Higher-risk TLD", "." + tld + " links need extra context before trust.",14); }

    if (brands.length && !bankFamily) {
      const brandNames = brands.map(b => b.name).join(", ");
      score -= 18;
      addSignal(signals,"high","Brand outside verified root","Brand language appears in the target, but the root domain is not part of the known family: " + brandNames + ".",18);
    }

    const urlStructureTitles = new Set([
      "Very long URL structure","Long URL structure","Numeric host-label deception","Deep path nesting",
      "Heavy URL encoding density","Nested URL encoding","Nested destination-like value","Opaque query payload",
      "Dense account-access wording","Heavy subdomain stack","Extra subdomain layers","Heavy hyphen use",
      "Encoded characters","Unusual network port","Higher-risk TLD"
    ]);
    const structuralMediums = signals.filter(function(signal){ return signal && signal.severity === "medium" && urlStructureTitles.has(signal.title); });
    const hasHardStructuralStop = signals.some(function(signal){
      return signal && signal.severity === "high" && /Unicode|punycode|IP address|Username-in-link|Brand outside|lookalike|Near-miss|Trusted root stuffed|double-extension|Executable/i.test(signal.title || "");
    });
    if (!trustedStructureRelief && !hasHardStructuralStop && structuralMediums.length >= 3) {
      const weight = structuralMediums.length >= 5 ? 16 : 10;
      score -= weight;
      addSignal(signals, structuralMediums.length >= 5 ? "high" : "medium", "Compound URL deception pattern", "Several individually moderate URL-structure clues appear together: " + structuralMediums.slice(0,5).map(function(signal){ return signal.title; }).join(", ") + ". QANTRAE raises confidence in the warning because multiple independent concealment clues are present at the same time.", weight);
      timeline.push("v3.55 combined independent URL-structure clues instead of judging each one in isolation.");
    }

    if (isTrusted || bankFamily) {
      score += 8;
      addSignal(signals,"low","Known trusted root","The root domain matches a local trusted or known-family pattern. This helps, but it does not verify sender context or live page safety.",-8);
      if (attachmentIntent && attachmentIntent.trustedBenignCloudFile) {
        addSignal(signals,"low","Trusted cloud-file context","A document-style file appears on a known cloud/share root without executable, archive, pressure, or brand-mismatch evidence. v3.04 keeps this calm while still advising sender/source verification.",-2);
        trust.push("v3.04 trusted cloud-file false-positive relief applied for " + root + ".");
        technical.push("v3.04 false-positive tuning: trusted cloud document link did not trigger attachment-trap escalation.");
      }
      trust.push("Trusted-root relief applied for " + root + ".");
      const safeContextRelief = classifySafeTrustedContextRelief(target, signals, messageContext);
      if (safeContextRelief.active) {
        score += safeContextRelief.safetyBoost;
        addSignal(signals,"low",safeContextRelief.title,safeContextRelief.detail,-safeContextRelief.safetyBoost);
        trust.push("v2.90 safe/trusted context relief applied (" + safeContextRelief.level + ") for " + root + ".");
        technical.push("v2.90 safe/trusted context relief: " + safeContextRelief.detail);
        timeline.push("v2.90 checked whether known-root workflow wording deserved relief instead of extra warning weight.");
      }
    } else {
      trust.push("No trusted-root relief applied for " + root + ".");
    }

    if (signals.filter(s => s.severity === "high").length >= 2) timeline.push("Multiple high-severity signals were found, so the final recommendation becomes more protective.");
    if (!signals.some(s => s.severity !== "low")) timeline.push("No major local red flag was found, but this remains a local offline scan, not a live reputation check.");

    technical.push("Root domain: " + root + ".");
    technical.push("Subdomain depth: " + subdomainDepth + ".");
    technical.push("TLD: ." + tld + ".");
    technical.push("Username section present: " + (target.username ? "yes" : "no") + ".");
    technical.push("Custom port present: " + (target.port ? target.port : "no") + ".");
    technical.push("Build: " + BUILD.version + " " + BUILD.name + ".");
    technical.push("v3.55 URL Intelligence Expansion adds calibrated URL-length tiers, numeric host-label review, deep-path analysis, encoding-density review, nested encoding/destination detection, opaque-query review, dense account-access wording, and compound structural escalation. Existing v3.12 modern scam coverage and v3.04 false-positive tuning remain preserved.");
    technical.push("v3.55 URL anatomy: " + urlIntel.length + " chars; " + urlIntel.hostLabels + " host labels; " + urlIntel.pathDepth + " path layers; " + urlIntel.percentCount + " encoded bytes; structural flags: " + (urlIntel.structuralFlags.join(", ") || "none") + ".");

    return finalize({target, score, signals, technical, trust, timeline});
  }


  function makeLinkAnatomy(target){
    const empty = { status:"Waiting for input", protocol:"—", host:"—", root:"—", path:"—", query:"—", tokens:"—", note:"Proxuma will break the target into readable parts after a scan." };
    if (!target || target.type === "empty") return empty;
    const raw = String(target.sourceRaw || target.raw || "").trim();
    if (target.type !== "url") {
      const candidates = Array.isArray(target.embeddedCandidates) ? target.embeddedCandidates : [];
      const decoded = safeDecodeForInspection(raw || target.raw || "");
      const workflowHits = Array.from(highValueWorkflowWords || []).filter(word => decoded.toLowerCase().includes(word)).slice(0, 6);
      const payloadEndingSpoof = inspectDomainEndingSpoof(target);
      const encodedTokens = inspectEncodedRiskTokens(target);
      const payloadTokens = workflowHits.concat(encodedTokens);
      if (payloadEndingSpoof.active) payloadTokens.unshift(payloadEndingSpoof.token || payloadEndingSpoof.kind);
      return {
        status: target.type === "dangerous-scheme" ? "Non-web / script-style payload" : "Message / QR payload",
        protocol: target.scheme || "payload",
        host: target.host || "Non-URL payload",
        root: candidates.length ? "Embedded URL found" : "No root domain",
        path: raw ? (raw.length > 90 ? raw.slice(0, 87) + "…" : raw) : "Payload text",
        query: candidates.length ? (candidates.length + " embedded link" + (candidates.length === 1 ? "" : "s")) : "No URL query",
        tokens: payloadTokens.length ? Array.from(new Set(payloadTokens)).slice(0, 10).join(", ") : "No URL tokens",
        note: "This input is being treated as message/QR/payload content, so Proxuma shows payload structure instead of pretending it is a normal web link."
      };
    }
    let url = null;
    try { url = new URL(target.display || target.href || target.raw); } catch(error) { url = null; }
    const pathOnly = url ? (url.pathname || "/") : String(target.path || "/").split("?")[0];
    const queryKeys = [];
    if (url) url.searchParams.forEach((value, key) => { if (queryKeys.length < 8) queryKeys.push(key || "unnamed"); });
    const surface = String((target.host || "") + " " + (target.path || "")).toLowerCase();
    const tokenHits = [];
    Array.from(highValueWorkflowWords || []).forEach(word => {
      if (surface.includes(word) && tokenHits.length < 8) tokenHits.push(word);
    });
    Array.from(redirectParamNames || []).forEach(word => {
      const q = queryKeys.join(" ").toLowerCase();
      if (q.includes(word) && tokenHits.length < 8) tokenHits.push("redirect:" + word);
    });
    inspectEncodedRiskTokens(target).forEach(token => {
      if (tokenHits.length < 10) tokenHits.push(token);
    });
    const endingSpoof = inspectDomainEndingSpoof(target);
    if (endingSpoof.active && tokenHits.length < 10) tokenHits.push(endingSpoof.token || endingSpoof.kind);
    return {
      status: "URL structure parsed locally",
      protocol: (target.scheme || (url && url.protocol.replace(":", "")) || "unknown").toUpperCase(),
      host: target.host || (url && url.hostname) || "Unknown host",
      root: target.root || "Unknown root",
      path: pathOnly || "/",
      query: queryKeys.length ? queryKeys.join(", ") : "No query parameters",
      tokens: tokenHits.length ? Array.from(new Set(tokenHits)).join(", ") : "No obvious structural risk tokens",
      note: "This anatomy view separates the visible URL parts from the score explanation so users can inspect the structure without opening a separate evidence drawer."
    };
  }

  function emptyReport(){
    return { score:0, risk:"Ready to scan", riskClass:"", target:"Waiting", root:"Waiting", count:0, next:"Enter a target", scanMode:"Standby", confidence:"Not measured", confidenceNote:"Paste a target to begin.", summary:"Enter a URL, domain, or QR payload to generate a report.", explain:"Run a scan to see the strongest reason behind the verdict.", evidence:["No target scanned yet."], technical:["Technical notes appear after analysis."], trust:["Input received — Waiting for a URL, domain, short link, download link, or QR payload.", "Target resolved — Proxuma will separate the visible words from the real root destination.", "Signals inspected — HTTPS, IP links, shorteners, lookalikes, risky files, and pressure words are checked locally.", "Risk explained — The report converts local signals into readable reason and heat level.", "Next move suggested — The final card tells the user whether to proceed, verify, or stop."], timeline:["Paste target", "Resolve true target", "Inspect local signals", "Explain risk", "Suggest next move"], threat:"Paste a target and Proxuma IT will explain what could be happening without overloading the main report.", learning:"A scan-specific safety takeaway will appear here.", online:"Offline result first. Future online checks can ask permission before checking domain age, certificates, redirects, and reputation.", severityMix:"0 high · 0 medium · 0 low", severityNote:"No signal mix yet.", decision:["Paste a target into the scan field.", "Use an example if you want to see the engine immediately.", "Review the Risk Score, heat bar, Primary Trigger, and Next Step first."], heatPercent:0, heatLabel:"Standby", primaryTrigger:"Waiting", laneQuality:"Standby", evidenceStrength:"Waiting", confidenceBrief:"Waiting", whyScore:"Waiting for local evidence.", scanMemory:"No previous scan", compareLast:"Waiting for the first scan.", raw:"", time:"", inputType:"Standby", anatomy:makeLinkAnatomy({type:"empty"}) };
  }


  function makePrimaryTrigger(dominant, score, high, medium){
    if (dominant) return dominant.title;
    if (score <= 9) return "No major local red flag";
    if (high) return "High-severity signal";
    if (medium) return "Caution signal";
    return "Local structure review";
  }

  function makeLaneQuality(target, risk){
    if (target.type === "payload") return "Payload / QR text";
    if (risk === "High Risk") return "Blocked lane";
    if (risk === "Needs Review") return "Review lane";
    return "Clean lane";
  }

  function makeInputType(target){
    if (!target || !target.raw) return "Standby";
    if (target.type === "dangerous-scheme") return "Script Payload";
    if (target.type === "payload") {
      if (/^\d{6,}$/.test(target.raw)) return "QR Numeric";
      if (/^unreadable$/i.test(target.scheme)) return "Unreadable Input";
      return "QR Text";
    }
    if (hasMalformedDomainPunctuation(target)) return "Malformed Input";
    if (target.scheme === "http") return "HTTP URL";
    if (target.scheme === "https") return "HTTPS URL";
    return "URL / Domain";
  }



  function compactHashText(value){
    const text = String(value || "");
    let hash = 2166136261;
    for (let i = 0; i < text.length; i++) {
      hash ^= text.charCodeAt(i);
      hash = Math.imul(hash, 16777619);
    }
    return (hash >>> 0).toString(16).padStart(8, "0");
  }

  function makeCaseReference(seed){
    const d = new Date();
    const stamp = d.getFullYear() + String(d.getMonth()+1).padStart(2,"0") + String(d.getDate()).padStart(2,"0");
    return "PX-" + stamp + "-" + compactHashText(seed).slice(0,4).toUpperCase();
  }

  function buildEvidenceCasePacket(ctx, risk, score, evidenceProfile, dominant, high, medium, low){
    const raw = String((ctx.target && ctx.target.raw) || "");
    const root = (ctx.target && ctx.target.root) || "unknown";
    const host = (ctx.target && ctx.target.host) || "unknown";
    const packetSeed = [raw, root, risk, score, BUILD.version].join("|");
    const packetId = "PX-" + compactHashText(packetSeed);
    const caseReference = makeCaseReference(packetSeed);
    const localDigest = compactHashText(packetSeed);
    const capture = [
      "Preserve the exact raw input exactly as received.",
      "Record where it came from: email, SMS, QR code, chat, browser, ticket, or unknown.",
      "Keep screenshots or the original message when available.",
      "Do not click, log in, download, or enter one-time codes from the target.",
      "Verify through a trusted route typed manually or through an existing official app/bookmark."
    ];
    if (risk === "High Risk") capture.unshift("Treat this as an escalation packet before interacting with the target.");
    if ((ctx.target && ctx.target.type) === "payload") capture.push("If this is a QR/text payload, preserve the full payload text and scan any extracted URL as its own child case.");
    const chain = [
      "Raw input captured locally",
      "Candidate target normalized",
      "Root domain resolved as " + root,
      "Local evidence signals counted: " + high + " high, " + medium + " medium, " + low + " low",
      "Final verdict generated offline: " + risk + " at " + score + "/100"
    ];
    const summary = [
      "Case Packet: " + packetId,
      "Case Reference: " + caseReference,
      "Target/root: " + host + " / " + root,
      "Verdict: " + risk + " (" + score + "/100)",
      "Primary evidence: " + (dominant ? dominant.title : "No single dominant trigger"),
      "Evidence classes: " + evidenceProfileSummary(evidenceProfile),
      "Privacy: local-only analysis; no live reputation, threat-intel API, telemetry, or hidden online expansion was used for this verdict."
    ];
    return {
      id: packetId,
      caseReference,
      summary,
      chain,
      capture,
      evidenceCounts: { high, medium, low, critical:evidenceProfile.critical.length, strong:evidenceProfile.strong.length, moderate:evidenceProfile.medium.length, weak:evidenceProfile.weak.length, positive:evidenceProfile.positive.length },
      professionalSummary: "Proxuma IT reviewed this target locally. Verdict: " + risk + " (" + score + "/100). Root: " + root + ". Primary evidence: " + (dominant ? dominant.title : "no single dominant trigger") + ". Recommendation: " + (risk === "High Risk" ? "do not proceed; verify through a trusted route." : (risk === "Needs Review" ? "pause and verify source/root before action." : "proceed only with normal caution.")),
      digest: compactHashText(summary.concat(chain).concat(capture).join("|")),
      localDigest
    };
  }

  function finalize(ctx){
    // The engine internally still starts from a trust/safety number, then subtracts
    // warnings. For the Proxuma ecosystem UI, we convert that into Risk Score:
    // 0 = clean/safe, 100 = critical/danger.
    const safetyScore = Math.max(0, Math.min(100, Math.round(ctx.score)));
    let score = Math.max(0, Math.min(100, 100 - safetyScore));

    const high = ctx.signals.filter(s => s.severity === "high").length;
    const medium = ctx.signals.filter(s => s.severity === "medium").length;
    const low = ctx.signals.filter(s => s.severity === "low").length;
    const evidenceProfile = buildEvidenceProfile(ctx.signals);
    const criticalCount = evidenceProfile.critical.length;
    const strongCount = evidenceProfile.strong.length;

    // Protective overrides: major warning signals must never appear as low risk
    // just because a trusted-looking word or domain relief exists elsewhere.
    if (high >= 2) score = Math.max(score, 80);
    else if (high === 1) score = Math.max(score, 60);
    else if (medium >= 2) score = Math.max(score, 35);

    if (criticalCount >= 1) score = Math.max(score, 70);
    else if (strongCount >= 2) score = Math.max(score, 60);
    else if (strongCount === 1 && medium >= 1) score = Math.max(score, 48);
    else if (medium === 1 && high === 0 && strongCount === 0) score = Math.min(score, 32);
    if (criticalCount === 0 && strongCount === 0 && high === 0 && medium <= 1 && isKnownRoot(ctx.target)) score = Math.min(score, 18);

    score = calibrateRiskScore(score, ctx, high, medium, low);
    ctx.technical.push("Score calibration: applied v2.42-v2.46 hardening, v2.47 evidence-weight/confidence calibration, v2.49 guidance, v2.50 mismatch review, v2.51 HTML-anchor mismatch review, v2.52 copy/paste message intelligence, v2.53 brand-family expansion, and v2.54 report clarity polish, v2.57 shortener/relay intelligence, v2.58 copied email HTML intelligence, and v2.71 trusted share-wrapper intelligence and v2.87 dominant-threat cleanup, v2.88 calm scoring explanation/action triage, and v2.90 safe/trusted context relief before final verdict.");

    let risk = "Low Risk";
    let riskClass = "risk-low";
    let next = "Proceed with normal caution";
    let summary = "No major local red flag was found in the visible structure. Proxuma keeps this low, but still recommends normal caution for logins, payments, downloads, or private data.";

    if (score >= 60 || high >= 2) { risk = "High Risk"; riskClass = "risk-high"; next = "Do not enter info"; summary = "This target shows strong local warning signs. Treat it as unsafe for credentials, payment details, downloads, and personal information unless you verify it through a trusted route."; }
    else if (score >= 20 || high || medium >= 2) { risk = "Needs Review"; riskClass = "risk-medium"; next = "Verify first"; summary = "This target needs a second look. Proxuma found caution evidence, so verify the sender, root domain, and reason for the link before acting."; }

    const evidence = ctx.signals.length ? ctx.signals.map(s => (s.weightClass ? "[" + s.weightClass.toUpperCase() + "] " : "") + s.title + " — " + s.detail) : ["No strong local warning signals found."];
    const dominant = selectDominantSignal(ctx, evidenceProfile);
    const confidence = makeConfidence(score, high, medium, ctx.target, evidenceProfile);
    const threat = makeThreatStory(ctx.target, risk, dominant, high, medium);
    const learning = makeLearning(ctx.target, dominant, risk);
    const online = "Online Intel remains consent-first. v2.93.0 formalizes the permission gate, provider scope manifest, and request plan; live lookups remain locked off while simplifying the public scanner, analysis layers, case-file language, and release surface.";
    const severityMix = high + " high · " + medium + " medium · " + low + " low | Evidence: " + evidenceProfileSummary(evidenceProfile);
    const heatPercent = Math.max(0, Math.min(100, score));
    const heatLabel = score >= 60 || high >= 2 ? "Hot / High Risk" : (score >= 20 || high || medium >= 2 ? "Warm / Review" : "Cool / Low Risk");
    const severityNote = makeSeverityNote(high, medium, low, score);
    const decision = makeDecisionGuide(risk, ctx.target, high, medium, dominant);
    const primaryTrigger = makePrimaryTrigger(dominant, score, high, medium);
    next = makeRecommendedAction(risk, ctx.target, dominant);
    const whyScore = makeScoreExplanation(score, ctx.target, dominant, high, medium, low);
    const laneQuality = makeLaneQuality(ctx.target, risk);
    const evidenceStrength = makeEvidenceStrength(score, high, medium, low, ctx.target);
    const confidenceBrief = makeConfidenceBrief(confidence.label);
    const reportQuality = makeReportQualityBundle(risk, ctx.target, dominant, confidence, evidenceProfile);
    const clarity = makeClarityBundle(risk, ctx.target, dominant, confidence, evidenceProfile);
    const viewSplit = makeViewSplitBundle(risk, ctx.target, dominant, confidence, evidenceProfile, score);
    const calmTriage = makeCalmTriage(risk, score, ctx.target, dominant, evidenceProfile, high, medium, low);
    const whatToDoNext = makeWhatToDoNextGuidance(risk, ctx.target, dominant, calmTriage, evidenceProfile);
    const consistency = makeReportConsistencyPack(risk, ctx.target, dominant, whatToDoNext, evidenceProfile);
    ctx.technical.push("Report quality layer: " + reportQuality.audienceMode + " / tags: " + reportQuality.reportTags.join(", ") + ".");
    ctx.technical.push("v2.88 calm scoring/action triage: " + calmTriage.rationale + " Recommended action: " + calmTriage.action + ".");
    ctx.technical.push("v2.92 what-to-do-next language: " + whatToDoNext.actionTitle + " / " + whatToDoNext.whyTitle + ".");
    ctx.technical.push("v2.62 audience split layer: generated separate user-facing safety brief and analyst triage brief locally.");
    ctx.technical.push("Report clarity layer: quick summary, primary reason, supporting evidence, lower-weight clues, and trust-relief notes generated locally.");
    ctx.technical.push("Evidence weight profile: " + evidenceProfileSummary(evidenceProfile) + ".");
    ctx.technical.push("Highest evidence class: " + highestEvidenceClass(evidenceProfile) + ".");
    ctx.technical.push("v2.87/v3.19.5 dominant threat cleanup: " + summarizeDominantThreat(dominant, evidenceProfile) + ".");
    ctx.technical.push("v3.01 threat lane index: " + (dominant ? getThreatLane(dominant.family || classifySignalFamily(dominant)).id + " / " + getThreatLane(dominant.family || classifySignalFamily(dominant)).label : "No active lane") + " mapped from the centralized offline lane index.");
    ctx.technical.push("v3.02 report consistency pass: " + consistency.laneId + " aligned across What happened, Why it matters, What to do next, Safety habit, copied reports, and case packet fields.");
    const casePacket = buildEvidenceCasePacket(ctx, risk, score, evidenceProfile, dominant, high, medium, low);
    ctx.technical.push("v2.68 evidence case packet: generated " + casePacket.id + " with preservation checklist and local evidence digest " + casePacket.digest + ".");
    ctx.technical.push("v2.72 evidence case packet upgrade: professional summary, local JSON export, case reference " + casePacket.caseReference + ", evidence chain, counts, and preservation guidance generated locally.");
    ctx.technical.push("v2.93 optional online intel gate prep: provider scope manifest, request plan, consent disclosure, and offline fallback prepared with no active network/API provider.");
    describeIgnoredSignals(evidenceProfile).forEach(item => ctx.technical.push("v2.47 weighting note: " + item + "."));

    return { score, safetyScore, risk, riskClass, target:ctx.target.host, root:ctx.target.root, count:ctx.signals.length, next, scanMode:ctx.target.type === "payload" ? "Payload lane" : "URL/domain lane", confidence:confidence.label, confidenceNote:confidence.note, summary:clarity.quickSummary, explain: dominant ? dominant.title + ": " + dominant.detail : summary, evidence, technical:ctx.technical, trust:ctx.trust, timeline:ctx.timeline, threat, learning, online, severityMix, severityNote, decision, heatPercent, heatLabel, primaryTrigger, whyScore, laneQuality, evidenceStrength, confidenceBrief, audienceMode:reportQuality.audienceMode, plainVerdict:reportQuality.plainVerdict, userSteps:reportQuality.userSteps, orgEscalation:reportQuality.orgEscalation, reportTags:reportQuality.reportTags, topVerdict:clarity.topVerdict, quickSummary:clarity.quickSummary, whyThisMatters:clarity.whyThisMatters, primaryReason:clarity.primaryReason, supportingEvidence:clarity.supportingEvidence, lowerWeightClues:clarity.lowerWeightClues, trustReliefNotes:clarity.trustReliefNotes, reportOneLine:clarity.reportOneLine, userBrief:viewSplit.userBrief, analystBrief:viewSplit.analystBrief, analystDisposition:viewSplit.analystDisposition, triagePriority:viewSplit.triagePriority, scoreBand:calmTriage.band, actionTriage:calmTriage.action, calmScoreRationale:calmTriage.rationale, calmUserGuidance:calmTriage.user, whatToDoNext, reportConsistency:consistency, whatHappened:consistency.whatHappened, reportWhyItMatters:consistency.whyItMatters, reportWhatToDoNext:consistency.whatToDoNext, safetyHabit:consistency.safetyHabit, threatLaneId:consistency.laneId, threatLaneLabel:consistency.laneLabel, threatLaneReportName:consistency.laneReportName, threatLaneAction:consistency.laneAction, reportChecklist:consistency.reportChecklist, analystLaneLine:consistency.analystLine, userStepsV292:whatToDoNext.steps, casePacketId:casePacket.id, caseReference:casePacket.caseReference, casePacketSummary:casePacket.summary, casePacketChain:casePacket.chain, preservationChecklist:casePacket.capture, caseProfessionalSummary:casePacket.professionalSummary, evidenceCounts:casePacket.evidenceCounts, evidenceDigest:casePacket.digest, localDigest:casePacket.localDigest, anatomy:makeLinkAnatomy(ctx.target), raw:ctx.target.raw, inputType:makeInputType(ctx.target), time:formatReportTime(new Date()), displayTime:formatCompactReportTime(new Date()), high, medium, low };
  }

  function makeEvidenceStrength(score, high, medium, low, target){
    if (target.type === "payload") return "Context needed";
    if (high >= 1 || medium >= 2) return "Strong evidence";
    if (medium === 1) return "Moderate evidence";
    if (score <= 12 && low >= 1) return "Clean-leaning evidence";
    if (score <= 12) return "Light clean evidence";
    return "Light evidence";
  }

  function makeConfidenceBrief(confidenceLabel){
    if (/warning/i.test(confidenceLabel)) return "Strong warning";
    if (/caution/i.test(confidenceLabel)) return "Review confidence";
    if (/clean/i.test(confidenceLabel)) return "Clean confidence";
    if (/Medium/i.test(confidenceLabel)) return "Medium confidence";
    return "Limited confidence";
  }


  function makeAudienceMode(reportLike){
    const risk = String((reportLike && reportLike.risk) || "");
    const target = (reportLike && reportLike.target) || {};
    if (target.type === "payload") return "QR/Text payload triage";
    if (/High Risk/.test(risk)) return "Block / escalate";
    if (/Needs Review/.test(risk)) return "Verify before action";
    return "Normal caution";
  }

  function makePlainLanguageVerdict(risk, target, dominant, confidence){
    if (target.type === "payload") {
      return "This is not being judged as a normal website. Proxuma first classifies what the QR/text payload appears to be, then tells the user whether to identify it, verify it, or stop.";
    }
    const root = target.root || "the resolved root";
    if (risk === "High Risk") {
      return "Do not continue from this link. The safest reading is that " + root + " has enough structural warning evidence to require stopping and verifying through a separate trusted route.";
    }
    if (risk === "Needs Review") {
      return "Do not treat this as confirmed safe yet. " + root + " needs a manual check because the local scan found caution evidence, even though it did not reach the strongest warning lane.";
    }
    return "The visible structure looks locally clean. Proxuma did not find a major offline warning pattern, but the user should still verify context before logging in, paying, or sharing private information.";
  }

  function makeUserSteps(risk, target, dominant){
    if (target.type === "payload") return [
      "Identify what the QR/text payload is supposed to represent before using it.",
      "If it contains or opens a link, scan that destination separately.",
      "Do not enter codes, passwords, payment details, or account information unless the source is trusted."
    ];
    if (risk === "High Risk") return [
      "Stop: do not click deeper, sign in, pay, download, or enter a code.",
      "Open the organization through a saved bookmark, official app, or typed address instead.",
      "If this came through work, school, bank, or a message thread, save the link and report it."
    ];
    if (risk === "Needs Review") return [
      "Compare the resolved root domain with the official domain you expected.",
      "Confirm the sender and reason for the link outside the original message.",
      "Use a bookmark or official app for logins, payments, deliveries, benefits, and account changes."
    ];
    return [
      "Proceed only if the link came from a context you expected.",
      "For sensitive tasks, prefer bookmarks, official apps, or typed addresses.",
      "Use optional online intelligence later when age, reputation, certificate, or redirect-chain proof matters."
    ];
  }

  function makeOrgEscalation(risk, target, dominant, confidence){
    if (target.type === "payload") return "Triage payload source and intended use before allowing it into a workflow. If it embeds a URL, scan the extracted URL as its own case.";
    if (risk === "High Risk") return "Escalate as a security case. Preserve the raw URL, source message, timestamp, screenshot if available, and Proxuma evidence list.";
    if (risk === "Needs Review") return "Hold for verification. Compare root domain, sender identity, expected business process, and any redirect/download behavior before approval.";
    return "No immediate escalation from local structure alone. Keep normal user-awareness guidance and use live reputation checks for high-value workflows.";
  }

  function makeReportTags(risk, target, dominant, profile){
    const tags = [];
    tags.push(target.type === "payload" ? "payload-lane" : "url-domain-lane");
    tags.push(risk === "High Risk" ? "block" : (risk === "Needs Review" ? "verify" : "low-local-risk"));
    if (profile && profile.critical && profile.critical.length) tags.push("critical-evidence");
    if (profile && profile.strong && profile.strong.length) tags.push("strong-evidence");
    const text = String((dominant && (dominant.title + " " + dominant.detail)) || "").toLowerCase();
    if (/brand|institution|bank|government|interac|delivery|telecom/.test(text)) tags.push("impersonation-watch");
    if (/redirect/.test(text)) tags.push("redirect-watch");
    if (/download|file/.test(text)) tags.push("download-watch");
    if (target.type === "payload" || /qr|payload/.test(text)) tags.push("qr-text-watch");
    return Array.from(new Set(tags)).slice(0,8);
  }



  function makeViewSplitBundle(risk, target, dominant, confidence, profile, score){
    profile = profile || {critical:[], strong:[], medium:[], weak:[], positive:[]};
    const root = target && target.root ? target.root : "unresolved target";
    const primary = dominant ? shortSignal(dominant) : "No single dominant signal.";
    const userHeadline = risk === "High Risk"
      ? "Stop before acting. This target has strong local warning signs."
      : (risk === "Needs Review" ? "Pause and verify. This target needs a second check." : "No major local warning signs, but context still matters.");
    const userBrief = [
      userHeadline,
      "Safest move: " + makeRecommendedAction(risk, target, dominant) + ".",
      "Main reason: " + primary,
      target && target.type === "payload" ? "This was treated as QR/text payload first, not forced into normal website scoring." : "Resolved root checked: " + root + "."
    ];
    const disposition = risk === "High Risk" ? "Block / do not proceed" : (risk === "Needs Review" ? "Hold for verification" : "Allow with normal caution");
    const triagePriority = risk === "High Risk" ? "P1 user-protection case" : (risk === "Needs Review" ? "P2 verification case" : "P3 awareness case");
    const evidenceClasses = [
      "Critical: " + profile.critical.length,
      "Strong: " + profile.strong.length,
      "Medium: " + profile.medium.length,
      "Weak: " + profile.weak.length,
      "Trust relief: " + profile.positive.length
    ].join(" · ");
    const analystBrief = [
      "Disposition: " + disposition,
      "Triage priority: " + triagePriority,
      "Confidence: " + ((confidence && confidence.label) || "local-only"),
      "Evidence classes: " + evidenceClasses,
      "Primary evidence: " + primary,
      "Offline limitation: no live reputation, certificate, WHOIS/domain-age, or redirect-chain request was made."
    ];
    return { userBrief, analystBrief, analystDisposition: disposition, triagePriority };
  }

  function makeReportQualityBundle(risk, target, dominant, confidence, profile){
    return {
      audienceMode: makeAudienceMode({risk, target}),
      plainVerdict: makePlainLanguageVerdict(risk, target, dominant, confidence),
      userSteps: makeUserSteps(risk, target, dominant),
      orgEscalation: makeOrgEscalation(risk, target, dominant, confidence),
      reportTags: makeReportTags(risk, target, dominant, profile)
    };
  }


  function shortSignal(signal){
    if (!signal) return "No single dominant signal.";
    return signal.title + " — " + signal.detail;
  }

  function makeTopVerdictLine(risk, target, dominant){
    const root = target && target.root ? target.root : "this target";
    if (target && target.type === "payload") {
      if (risk === "High Risk") return "High Risk — do not use this QR/text payload until verified.";
      if (risk === "Needs Review") return "Needs Review — identify this QR/text payload before acting.";
      return "Low Risk — this looks like a simple QR/text payload, not a dangerous web destination.";
    }
    if (risk === "High Risk") return "High Risk — do not click or enter information.";
    if (risk === "Needs Review") return "Needs Review — verify the source and real root domain first.";
    return "Low Risk — no major offline warning signs found for " + root + ".";
  }

  function makeHumanWhy(risk, target, dominant, profile){
    if (target && target.type === "payload") {
      return risk === "Low Risk"
        ? "Proxuma treated the input as a payload instead of forcing it into website scoring. Context still matters before using codes or QR data."
        : "The payload contains message, link, pressure, or structure clues that need verification before it is used.";
    }
    const root = target && target.root ? target.root : "the resolved root";
    const domText = String((dominant && (dominant.title + " " + dominant.detail)) || "");
    if (/brand|mismatch|stuffed|embedded|lookalike|near-miss/i.test(domText)) return "The visible brand words do not safely match the real root domain controlling the destination.";
    if (/redirect/i.test(domText)) return "The link uses a redirect-style path or parameter, so the shown address may not be the final place the user is being pushed.";
    if (/pressure|urgent|verify|account|payment|locked|delivery/i.test(domText)) return "The message uses urgency or account/payment language, which is often used to rush people past normal checks.";
    if (/file|download|extension/i.test(domText)) return "The target looks like it may involve a risky or disguised file download.";
    if (risk === "High Risk") return "Several strong local clues point away from a normal trusted destination.";
    if (risk === "Needs Review") return root + " has enough caution evidence to require a second check before sensitive action.";
    return "The real root domain and visible structure did not trigger major offline warning patterns.";
  }

  function makeEvidenceHierarchy(profile, dominant){
    profile = profile || {critical:[], strong:[], medium:[], weak:[], positive:[]};
    const primary = dominant ? [shortSignal(dominant)] : ["No single dominant threat signal." ];
    const supporting = profile.critical.concat(profile.strong).filter(s => s !== dominant).slice(0,4).map(shortSignal);
    const lower = profile.medium.concat(profile.weak).slice(0,5).map(shortSignal);
    const relief = profile.positive.slice(0,4).map(shortSignal);
    return {
      primaryReason: primary,
      supportingEvidence: supporting.length ? supporting : ["No additional critical/strong supporting signal dominated the result."],
      lowerWeightClues: lower.length ? lower : ["No lower-weight clues dominated the decision."],
      trustReliefNotes: relief.length ? relief : ["No trust-relief signal overrode the final verdict."]
    };
  }

  function makeClarityBundle(risk, target, dominant, confidence, profile){
    const topVerdict = makeTopVerdictLine(risk, target, dominant);
    const why = makeHumanWhy(risk, target, dominant, profile);
    const hierarchy = makeEvidenceHierarchy(profile, dominant);
    let quickSummary = topVerdict + " " + why;
    if (risk === "High Risk") quickSummary += " Safest move: stop and reach the organization through an official app, saved bookmark, or typed address.";
    else if (risk === "Needs Review") quickSummary += " Safest move: verify outside the original message before continuing.";
    else quickSummary += " Safest move: proceed only in the expected context, especially for logins, payments, downloads, or private data.";
    return Object.assign({
      topVerdict,
      quickSummary,
      whyThisMatters: why,
      reportOneLine: topVerdict + " Confidence: " + (confidence && confidence.label ? confidence.label : "local-only") + "."
    }, hierarchy);
  }

  function makeConfidence(score, high, medium, target, profile){
    profile = profile || {critical:[], strong:[], medium:[], weak:[], positive:[]};
    if (target.type === "payload") {
      if (profile.critical.length || high) return {label:"High confidence warning", note:"Payload classification found a high-risk authority, scheme, or embedded-link pattern."};
      return {label:"Medium confidence", note:"Payload type is classified locally, but context decides what the payload means."};
    }
    if (profile.critical.length) return {label:"High confidence warning", note:"Critical evidence was found. This is not just a weak suspicious word."};
    if (profile.strong.length >= 2 || high >= 2) return {label:"High confidence warning", note:"Multiple strong or high-severity signals agree with the risk verdict."};
    if (profile.strong.length || high) return {label:"Medium-high confidence warning", note:"A strong local signal was found, but offline mode cannot verify live reputation."};
    if (score <= 12 && isKnownRoot(target)) return {label:"High confidence clean", note:"The root matches a known family and no medium/strong/critical local evidence dominated."};
    if (score <= 12) return {label:"Medium confidence clean", note:"Structure looks readable, but no live reputation lookup was used."};
    if (medium || profile.medium.length) return {label:"Medium confidence caution", note:"Caution signals were found, but they did not rise to critical evidence."};
    return {label:"Limited confidence", note:"The local scan found little, but absence of evidence is not proof of safety."};
  }

  function makeSeverityNote(high, medium, low, score){
    if (high >= 2) return "Multiple high signals override a clean-looking design.";
    if (high === 1) return "One high signal is enough to slow down and verify through another route.";
    if (medium >= 2) return "Several caution signals combine into a stronger review warning.";
    if (score <= 12 && low >= 1) return "Mostly clean structure with local trust relief, but no live reputation check.";
    if (!high && !medium && !low) return "No signal mix was generated.";
    return "Signal mix is light, so context and sender trust matter most.";
  }

  function makeScoreExplanation(score, target, dominant, high, medium, low){
    const band = makeScoreBand(score);
    const lane = dominant ? (dominant.family || classifySignalFamily(dominant)) : "no dominant lane";
    if (target.type === "payload") {
      return score <= 20
        ? band.label + ": low web risk because this is not a normal URL, but context still decides what the payload means."
        : band.label + ": raised because the QR/text payload contains context, pressure, link, or action clues that should be identified before use.";
    }
    if (dominant && high >= 1) {
      return band.label + ": raised mainly by " + dominant.title + " (" + lane + "). High-severity evidence puts the result into protective mode.";
    }
    if (dominant && medium >= 2) {
      return band.label + ": raised by multiple caution signals, led by " + dominant.title + " (" + lane + "). Combined clues can matter even when each clue is not critical alone.";
    }
    if (dominant && medium === 1) {
      return band.label + ": slightly raised by " + dominant.title + " (" + lane + "). Verify context before sensitive action.";
    }
    if (low >= 1 && score <= 12) {
      return band.label + ": kept low because local evidence stayed minor and trust-relief/evidence-weight calibration prevented over-punishment.";
    }
    if (score <= 12) {
      return band.label + ": kept low because no strong local warning signal was found in the visible structure.";
    }
    return band.label + ": based on local structure, signal mix, and the strongest visible evidence found in the target.";
  }

  function makeRecommendedAction(risk, target, dominant){
    if (target.type === "payload") return "Identify payload before use";
    if (risk === "High Risk") {
      if (dominant && /download|file/i.test(dominant.title + dominant.detail)) return "Block download";
      if (dominant && /IP address/i.test(dominant.title)) return "Do not trust IP link";
      return "Stop and verify elsewhere";
    }
    if (risk === "Needs Review") return "Verify source first";
    return "Proceed with normal caution";
  }

  function makeDecisionGuide(risk, target, high, medium, dominant){
    if (target.type === "payload") return [
      "Do not treat the QR/text as a normal website automatically.",
      "Identify whether it is an ID, product code, ticket number, payment code, or hidden instruction.",
      "Verify where it came from before entering it into another system."
    ];
    if (risk === "High Risk") return [
      "Do not enter usernames, passwords, payment info, or personal data.",
      "Do not download or open attached files from this target.",
      "Reach the organization from a known bookmark, official app, or typed address.",
      "Save the case file if this came from a message, QR code, or workplace report."
    ];
    if (risk === "Needs Review") return [
      "Compare the root domain with the official site you expected.",
      "Check the sender and reason for the link before clicking further.",
      "Avoid sensitive actions until the source is confirmed.",
      dominant ? "Focus first on: " + dominant.title + "." : "Look for the strongest warning signal first."
    ];
    return [
      "Structure looks locally clean, but keep normal caution.",
      "For logins or payments, prefer typed addresses or saved bookmarks.",
      "Use optional online checks later when domain age, certificate, or reputation matters."
    ];
  }

  function makeThreatStory(target, risk, dominant, high, medium){
    if (!dominant) return "No dominant threat pattern appeared. Treat the result as local guidance, not a guarantee.";
    if (target.type === "payload") return "This looks like a QR/text payload rather than a web destination. The safest path is to verify what the code represents before scanning it into another system or sharing it.";
    if (risk === "High Risk") return "Likely threat path: the user is pushed toward " + target.root + " through wording or structure that lowers trust. The safest move is to stop, avoid entering information, and reach the organization through a known trusted route.";
    if (risk === "Needs Review") return "Possible caution path: the destination may be legitimate or may be imitating a trusted workflow. Verify the sender, root domain, and reason for the link before continuing.";
    return "Clean-looking path: the destination structure did not trigger major local warnings. Still confirm the source, especially before logins, payments, downloads, or private data.";
  }

  function makeLearning(target, dominant, risk){
    if (target.type === "payload") return "Safety takeaway: not every QR code is a link. First decide whether it is a URL, an ID, a product code, or another payload type.";
    if (!dominant) return "Safety takeaway: read the root domain first. Brand words, login words, and urgent wording matter less than the actual root domain controlling the page.";
    if (/Brand|lookalike|Unicode|punycode/i.test(dominant.title)) return "Safety takeaway: do not trust brand words alone. The root domain decides where the link really goes.";
    if (/Pressure|urgent|verify|account/i.test(dominant.title + dominant.detail)) return "Safety takeaway: separate emotional pressure from the technical destination. Urgency and disguised login/account wording are persuasion tactics, not proof.";
    if (risk === "High Risk") return "Safety takeaway: one high-risk clue matters, but several clues together create the strongest warning.";
    return "Safety takeaway: verify three things before action — structure, source, and purpose. A clean-looking link can still be risky if the message context is wrong.";
  }


  function readLastScan(){
    try { return JSON.parse(localStorage.getItem(LAST_SCAN_KEY) || "null"); }
    catch { return null; }
  }

  function writeLastScan(report){
    if (!report || !report.raw) return;
    const memory = {
      score: report.score,
      risk: report.risk,
      root: report.root,
      target: report.target,
      primaryTrigger: report.primaryTrigger,
      count: report.count,
      time: report.time || new Date().toLocaleString()
    };
    try { localStorage.setItem(LAST_SCAN_KEY, JSON.stringify(memory)); } catch {}
  }


  function readPatternMemory(){
    try {
      const parsed = JSON.parse(localStorage.getItem(PATTERN_MEMORY_KEY) || "null");
      if (!parsed || typeof parsed !== "object") return { roots:{}, triggers:{}, total:0 };
      parsed.roots = parsed.roots || {};
      parsed.triggers = parsed.triggers || {};
      parsed.total = parsed.total || 0;
      return parsed;
    } catch {
      return { roots:{}, triggers:{}, total:0 };
    }
  }


  function formatMemoryFamilyName(value){
    return String(value || "unknown").replace(/-/g, " ").replace(/\b\w/g, ch => ch.toUpperCase());
  }

  function getTopMemoryEntries(collection, limit){
    return Object.entries(collection || {})
      .sort((a,b) => (b[1].count || 0) - (a[1].count || 0) || String(b[1].lastSeen || "").localeCompare(String(a[1].lastSeen || "")))
      .slice(0, limit || 5);
  }

  function renderMemoryList(el, entries, type){
    if (!el) return;
    el.innerHTML = "";
    if (!entries.length) {
      const li = document.createElement("li");
      li.textContent = type === "root" ? "No roots remembered yet." : "No pattern families remembered yet.";
      el.appendChild(li);
      return;
    }
    entries.forEach(([key, stats]) => {
      const li = document.createElement("li");
      const label = type === "root" ? key : formatMemoryFamilyName(key);
      const riskBits = [];
      if (stats.high) riskBits.push(stats.high + " high");
      if (stats.review) riskBits.push(stats.review + " review");
      if (stats.low) riskBits.push(stats.low + " low");
      li.innerHTML = "<b>" + escapeHtml(label) + "</b><br><small>" + escapeHtml(String(stats.count || 0)) + " scan" + ((stats.count || 0) === 1 ? "" : "s") + (riskBits.length ? " · " + escapeHtml(riskBits.join(" · ")) : "") + "</small>";
      el.appendChild(li);
    });
  }

  function makeMemorySummary(){
    const memory = readPatternMemory();
    const rootEntries = getTopMemoryEntries(memory.roots, 5);
    const familyEntries = getTopMemoryEntries(memory.triggers, 5);
    return [
      "Proxuma IT Local Memory Summary",
      "Version: v2.75.0 Consent-First Online Intel Architecture",
      "Privacy: browser-local only; no API call, telemetry, or full browsing history stored.",
      "Total remembered scans: " + (memory.total || 0),
      "Remembered roots: " + Object.keys(memory.roots || {}).length,
      "Pattern families: " + Object.keys(memory.triggers || {}).length,
      "",
      "Top remembered roots:",
      ...(rootEntries.length ? rootEntries.map(([key, stats]) => "- " + key + " · " + (stats.count || 0) + " scan(s) · last risk: " + (stats.lastRisk || "n/a")) : ["- None yet"]),
      "",
      "Pattern families:",
      ...(familyEntries.length ? familyEntries.map(([key, stats]) => "- " + formatMemoryFamilyName(key) + " · " + (stats.count || 0) + " scan(s)") : ["- None yet"])
    ].join("\n");
  }

  function renderPatternMemoryDashboard(){
    const memory = readPatternMemory();
    const roots = memory.roots || {};
    const triggers = memory.triggers || {};
    const rootCount = Object.keys(roots).length;
    const familyCount = Object.keys(triggers).length;
    if (els.memoryTotalScans) els.memoryTotalScans.textContent = String(memory.total || 0);
    if (els.memoryRootCount) els.memoryRootCount.textContent = String(rootCount);
    if (els.memoryFamilyCount) els.memoryFamilyCount.textContent = String(familyCount);
    if (els.memoryDashboardStatus) els.memoryDashboardStatus.textContent = (memory.total || 0) ? "Local memory active" : "No memory yet";
    renderMemoryList(els.memoryRootList, getTopMemoryEntries(roots, 5), "root");
    renderMemoryList(els.memoryFamilyList, getTopMemoryEntries(triggers, 5), "family");
    if (els.memoryDashboardNote) {
      els.memoryDashboardNote.textContent = (memory.total || 0)
        ? "Memory is active on this device only. Use Clear Pattern Memory to reset the learned pattern counters."
        : "Run a few scans to let Proxuma build local pattern awareness in this browser.";
    }
  }

  async function copyMemorySummary(){
    const summary = makeMemorySummary();
    try {
      await navigator.clipboard.writeText(summary);
      if (els.copyStatus) els.copyStatus.textContent = "Local memory summary copied.";
    } catch(error) {
      if (els.copyStatus) els.copyStatus.textContent = summary;
    }
  }

  function downloadMemoryJson(){
    const memory = readPatternMemory();
    const packet = {
      product: "Proxuma IT",
      version: BUILD.version,
      type: "local-pattern-memory-dashboard-export",
      privacy: "browser-local export; no API call was made by this action",
      exportedAt: new Date().toISOString(),
      totals: {
        scans: memory.total || 0,
        roots: Object.keys(memory.roots || {}).length,
        families: Object.keys(memory.triggers || {}).length
      },
      memory
    };
    const blob = new Blob([JSON.stringify(packet, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "proxuma-it-local-memory-v2.75.0.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    if (els.copyStatus) els.copyStatus.textContent = "Local memory JSON downloaded.";
  }

  function clearPatternMemory(){
    localStorage.removeItem(PATTERN_MEMORY_KEY);
    renderPatternMemoryDashboard();
    if (els.copyStatus) els.copyStatus.textContent = "Local pattern memory cleared. Saved cases were left alone.";
  }



  const ONLINE_INTEL_PROVIDER_MANIFEST = Object.freeze({
    version: "v3.27.0",
    networkActive: false,
    providersConnected: "architecture-only / user-opened-launchpad",
    providerArchitectureActive: false,
    requiresFreshConsent: true,
    plannedScopes: Object.freeze([
      { id:"domain-age", label:"Domain age", sends:"root domain only", purpose:"prepare a user-opened domain registration / RDAP lookup" },
      { id:"certificate-summary", label:"Certificate search", sends:"root domain only", purpose:"prepare a user-opened certificate transparency search" },
      { id:"redirect-expansion", label:"Redirect / URL context", sends:"submitted URL only if the user opens an external lookup", purpose:"prepare a user-opened URL analysis lookup" },
      { id:"reputation-provider", label:"Reputation search", sends:"root domain or URL only if the user opens an external lookup", purpose:"prepare a user-opened reputation / threat-intelligence search" },
      { id:"threat-feed-check", label:"Threat feed check", sends:"root domain, URL hash, or normalized URL only after explicit future provider consent", purpose:"reserve a future serverless threat-feed check slot; inactive in this build" }
    ]),
    hardRules: Object.freeze([
      "Offline scan must always run first.",
      "Online Intel must show scope before any provider-backed lookup.",
      "Consent must be revocable from the local browser.",
      "No silent telemetry, background lookup, or automatic submission is allowed.",
      "External lookups must be user-opened links, not hidden requests.",
      "If the provider is unavailable, Proxuma must fall back to the local report.",
      "API keys must never be placed in the GitHub Pages frontend; future provider checks must use a consent-gated serverless bridge."
    ])
  });


  const ONLINE_PROVIDER_ARCHITECTURE_SLOTS = Object.freeze([
    { id:"rdap-domain-age", status:"Planned / inactive", label:"Domain age / RDAP", futureData:"registration age, registrar hints, nameserver context", safety:"Root domain only; future lookup must run through a serverless bridge after consent." },
    { id:"certificate-transparency", status:"Planned / inactive", label:"Certificate transparency", futureData:"recent certificates, suspicious subdomain certificates, issuer timing", safety:"Root domain only; no certificate provider is contacted in this build." },
    { id:"redirect-expansion", status:"Planned / inactive", label:"Redirect expansion", futureData:"final destination, redirect chain length, mismatch between visible and final host", safety:"Submitted URL only after explicit consent; no automatic expansion in this build." },
    { id:"reputation-lookup", status:"Planned / inactive", label:"Reputation lookup", futureData:"known malicious reports, category hints, community/provider reputation", safety:"No frontend API keys; future provider checks require a serverless privacy boundary." },
    { id:"threat-feed-check", status:"Planned / inactive", label:"Threat feed check", futureData:"known threat matches, normalized URL/domain indicators, optional hash-based checks", safety:"Future-only slot; inactive until user-enabled Online Mode and backend protection exist." }
  ]);

  const ONLINE_READINESS_CHECKS = Object.freeze([
    { id:"offline-mode", label:"Online mode", inactive:"Off / offline-first", armed:"Armed preview only", detail:"No provider/API request runs automatically." },
    { id:"consent-state", label:"Consent status", inactive:"Not armed", armed:"Armed by user", detail:"Consent can be cleared locally at any time." },
    { id:"provider-slots", label:"Provider slots", inactive:"Mapped / inactive", armed:"Mapped / user-opened links only", detail:"RDAP, certificate, redirect, reputation, and threat-feed slots are planned, not connected." },
    { id:"api-key-safety", label:"API key status", inactive:"No browser key", armed:"No browser key", detail:"No API key or secret is stored in this GitHub Pages frontend." },
    { id:"serverless-bridge", label:"Serverless bridge", inactive:"Blueprint ready / not connected", armed:"Blueprint ready / not connected", detail:"Future automatic provider lookups must pass through a consent-gated serverless bridge; no live bridge is active in this build." },
    { id:"network-activity", label:"Network activity", inactive:"No hidden calls", armed:"No hidden calls", detail:"This build has no hidden browser network transport or provider path." }
  ]);

  function renderOnlineReadiness(report){
    if (!els.onlineReadinessList && !els.onlineReadinessStatus) return;
    const consent = readOnlineConsent();
    const armed = consent.status === "armed";
    if (els.onlineReadinessStatus) {
      els.onlineReadinessStatus.textContent = armed ? "Ready / gated" : "Offline / locked";
      els.onlineReadinessStatus.className = "status-pill " + (armed ? "status-medium" : "status-low");
    }
    if (!els.onlineReadinessList) return;
    els.onlineReadinessList.innerHTML = "";
    ONLINE_READINESS_CHECKS.forEach(function(check){
      const li = document.createElement("li");
      li.className = "online-readiness-item status-low";
      const strong = document.createElement("strong");
      strong.textContent = check.label + ": " + (armed ? check.armed : check.inactive);
      const small = document.createElement("small");
      small.textContent = check.detail;
      li.appendChild(strong);
      li.appendChild(small);
      els.onlineReadinessList.appendChild(li);
    });
  }

  function renderOnlineProviderArchitecture(){
    if (!els.onlineProviderSlotList) return;
    els.onlineProviderSlotList.innerHTML = "";
    ONLINE_PROVIDER_ARCHITECTURE_SLOTS.forEach(function(slot){
      const li = document.createElement("li");
      li.className = "online-provider-slot status-low";
      const strong = document.createElement("strong");
      strong.textContent = slot.label + " — " + slot.status;
      const small = document.createElement("small");
      small.textContent = "Future data: " + slot.futureData + ". Guardrail: " + slot.safety;
      li.appendChild(strong);
      li.appendChild(small);
      els.onlineProviderSlotList.appendChild(li);
    });
  }

  function makeOnlineIntelRequestPlan(report){
    const safeReport = report || lastReport || emptyReport();
    const root = safeReport.root && safeReport.root !== "Waiting" ? safeReport.root : "unresolved root";
    const raw = safeReport.raw || "no submitted target";
    return {
      build:"v3.29.3 rdap-fallback-host-awareness",
      networkActive:false,
      providerConnected:"Vercel RDAP bridge available when deployed on Vercel / consent-gated",
      consentRequired:true,
      targetRoot:root,
      submittedTargetPreview:String(raw).slice(0,160),
      scopes:ONLINE_INTEL_PROVIDER_MANIFEST.plannedScopes.map(function(scope){ return scope.id; }),
      disclosure:makeOnlineScopeDisclosure(root),
      fallback:"Use the existing offline Proxuma report if the user declines, the provider is unavailable, or the network is offline."
    };
  }

  function makeOnlineScopeDisclosure(root){
    return [
      "Online Intel is optional and off by default.",
      "Planned target for future lookup: " + (root || "the scanned root") + ".",
      "A user-opened Online Intel launchpad can prepare domain age, certificate search, redirect context, and reputation search links.",
      "The user must approve the scope before any external lookup link is generated.",
      "v3.29.3 keeps examples consolidated, preserves the serverless bridge prototype, and adds host-aware fallback messaging when RDAP is unavailable on GitHub Pages, local files, or unsupported hosts."
    ];
  }

  function readOnlineConsent(){
    try {
      const parsed = JSON.parse(localStorage.getItem(ONLINE_CONSENT_KEY) || "null");
      if (!parsed || parsed.status !== "armed") return { status:"off", updatedAt:null, scope:[] };
      return parsed;
    } catch(error) {
      return { status:"off", updatedAt:null, scope:[] };
    }
  }

  function writeOnlineConsent(state){
    try { localStorage.setItem(ONLINE_CONSENT_KEY, JSON.stringify(state)); } catch(error) {}
    renderOnlineConsentPanel(lastReport || emptyReport());
  }

  function revokeOnlineConsent(){
    try { localStorage.removeItem(ONLINE_CONSENT_KEY);
      localStorage.removeItem(ONLINE_FINDINGS_KEY); } catch(error) {}
    renderOnlineConsentPanel(lastReport || emptyReport());
    if (els.copyStatus) els.copyStatus.textContent = "Online Intel consent cleared. Proxuma is locked to offline-first mode.";
  }

  function enableOnlineConsent(){
    const state = {
      status:"armed",
      mode:"user-opened-online-launchpad",
      updatedAt:new Date().toISOString(),
      scope:ONLINE_INTEL_PROVIDER_MANIFEST.plannedScopes.map(function(scope){ return scope.id; }),
      networkActive:false,
      providerConnected:"user-opened-launchpad + consent-gated-rdap-bridge",
      requiresFreshConsent:true,
      note:"v3.29.3 allows a user-clicked RDAP bridge lookup only after consent is armed, with host-aware fallback messages when the bridge is not available. Proxuma still performs no hidden background lookup."
    };
    writeOnlineConsent(state);
    if (els.copyStatus) els.copyStatus.textContent = "Online Intel gate armed for future provider-backed checks. No network check was run.";
  }

  function makeOnlineArchitectureSummary(report){
    const consent = readOnlineConsent();
    const root = report && report.root && report.root !== "Waiting" ? report.root : "the scanned root";
    if (consent.status === "armed") {
      return "Online Intel gate is armed. Proxuma can generate user-opened lookup links for " + root + ", but it still makes no hidden fetch/API/background request.";
    }
    return "Online Intel is locked off. Proxuma will stay offline unless the user deliberately arms the explicit choice and opens an external lookup link.";
  }

  function renderOnlineConsentPanel(report){
    const consent = readOnlineConsent();
    const armed = consent.status === "armed";
    if (els.onlineConsentStatus) {
      els.onlineConsentStatus.textContent = armed ? "Consent gate armed" : "Offline locked";
      els.onlineConsentStatus.className = "status-pill " + (armed ? "status-medium" : "status-low");
    }
    if (els.onlineConsentDetail) {
      els.onlineConsentDetail.textContent = armed
        ? "Online Intel launchpad is armed. Generate lookup links only when you are ready to open an external site. Proxuma does not run hidden online checks."
        : "Online Intel is locked. The scanner, memory, QR, case packet layers, and lookup planning remain local until you arm consent.";
    }
    if (els.onlineScopeList) {
      if (armed) {
        renderOnlineLookupLaunchpad(report || lastReport || emptyReport());
      } else {
        renderList(els.onlineScopeList, ONLINE_INTEL_PROVIDER_MANIFEST.plannedScopes.map(function(scope){
          return scope.label + " — locked until consent; would send " + scope.sends + "; purpose: " + scope.purpose + ".";
        }));
      }
    }
    if (els.onlinePrivacyList) renderList(els.onlinePrivacyList, ONLINE_INTEL_PROVIDER_MANIFEST.hardRules);
    if (els.onlineArchitectureNote) els.onlineArchitectureNote.textContent = makeOnlineArchitectureSummary(report || lastReport || emptyReport());
    renderRdapSummary((lastReport && lastReport.rdapSummary) || latestRdapSummary);
    renderOnlineFindingsNotes();
    renderOnlineReadiness(report || lastReport || emptyReport());
    renderOnlineProviderArchitecture();
    if (els.onlinePreview) {
      els.onlinePreview.textContent = (report && report.raw ? report.online + " " : "") + makeOnlineArchitectureSummary(report || emptyReport());
      els.onlinePreview.className = "card-summary " + (armed ? "status-medium" : "status-low");
    }
  }

  function onlineSafeRoot(report){
    const candidate = String((report && report.root) || "").trim().toLowerCase();
    if (!candidate || candidate === "waiting" || candidate === "message" || candidate === "payload") return "";
    return candidate.replace(/^https?:\/\//, "").replace(/[^a-z0-9.-]/g, "").replace(/^www\./, "").slice(0,160);
  }

  function onlineLookupTargets(report){
    const safeReport = report || lastReport || emptyReport();
    const root = onlineSafeRoot(safeReport);
    const raw = String((safeReport && safeReport.raw) || "").trim();
    const encodedRoot = encodeURIComponent(root || "example.com");
    const encodedRaw = encodeURIComponent(raw || root || "example.com");
    return [
      { label:"Domain age / registration lookup", url:"https://rdap.org/domain/" + encodedRoot, note:"Opens an external RDAP-style domain lookup for the root domain." },
      { label:"Certificate transparency search", url:"https://crt.sh/?q=" + encodedRoot, note:"Opens an external certificate search for the root domain." },
      { label:"URL context search", url:"https://urlscan.io/search/#" + encodedRaw, note:"Opens an external URL context search using the submitted target." },
      { label:"General reputation search", url:"https://www.google.com/search?q=" + encodeURIComponent((root || raw || "target") + " scam phishing reputation"), note:"Opens a general web search for reputation context." }
    ];
  }

  function renderOnlineLookupLaunchpad(report){
    if (!els.onlineScopeList) return;
    const consent = readOnlineConsent();
    if (consent.status !== "armed") {
      renderList(els.onlineScopeList, ["Arm Online Intel consent before generating external lookup links."]);
      return;
    }
    const targets = onlineLookupTargets(report || lastReport || emptyReport());
    els.onlineScopeList.innerHTML = "";
    targets.forEach(function(target){
      const li = document.createElement("li");
      li.className = "online-launch-item status-medium";
      const a = document.createElement("a");
      a.href = target.url;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      a.textContent = target.label;
      const small = document.createElement("small");
      small.textContent = target.note;
      li.appendChild(a);
      li.appendChild(small);
      els.onlineScopeList.appendChild(li);
    });
  }

  function previewOnlineIntelRun(){
    const plan = makeOnlineIntelRequestPlan(lastReport || emptyReport());
    renderOnlineConsentPanel(lastReport || emptyReport());
    if (els.onlineArchitectureNote) els.onlineArchitectureNote.textContent = plan.disclosure.join(" ");
    if (els.copyStatus) els.copyStatus.textContent = "Online Intel request plan previewed locally. No hidden network request was made.";
  }

  function generateOnlineLookupLinks(){
    const consent = readOnlineConsent();
    if (consent.status !== "armed") {
      renderOnlineLookupLaunchpad(lastReport || emptyReport());
      if (els.copyStatus) els.copyStatus.textContent = "Arm Online Intel consent first. Proxuma did not open or send anything online.";
      return;
    }
    renderOnlineLookupLaunchpad(lastReport || emptyReport());
    if (els.onlineArchitectureNote) els.onlineArchitectureNote.textContent = "Lookup links generated locally. Nothing opens until you click a link; each link leaves Proxuma and opens an external site.";
    if (els.copyStatus) els.copyStatus.textContent = "Online lookup links generated. Proxuma did not run hidden fetch/API/background requests.";
  }


  function renderRdapSummary(summary){
    if (!els.onlineRdapResult) return;
    if (!summary) {
      els.onlineRdapResult.innerHTML = "<li>No RDAP result saved for this scan yet.</li>";
      return;
    }
    const rows = [
      "Domain: " + (summary.domain || "unknown"),
      "Registrar: " + (summary.registrarName || "not shown"),
      "Created: " + (summary.created || "not shown"),
      "Updated: " + (summary.updated || "not shown"),
      "Expires: " + (summary.expires || "not shown"),
      "Status: " + ((summary.status || []).join(", ") || "not shown")
    ];
    els.onlineRdapResult.innerHTML = "";
    rows.forEach(function(row){
      const li = document.createElement("li");
      li.textContent = row;
      els.onlineRdapResult.appendChild(li);
    });
  }

  function setRdapStatus(message, tone){
    if (!els.onlineRdapStatus) return;
    els.onlineRdapStatus.textContent = message;
    els.onlineRdapStatus.className = "status-pill " + (tone || "status-low");
  }

  function getRdapHostContext(){
    const loc = window.location || {};
    const protocol = String(loc.protocol || "").toLowerCase();
    const host = String(loc.hostname || "").toLowerCase();
    const origin = String(loc.origin || "");
    const isFile = protocol === "file:";
    const isGithubPages = host.endsWith("github.io");
    const isLocalhost = host === "localhost" || host === "127.0.0.1" || host === "::1";
    const isVercel = host.endsWith("vercel.app") || !!(window.PROXUMA_RDAP_BRIDGE_BASE);
    let label = "Serverless host not confirmed";
    let detail = "RDAP lookup requires a serverless deployment such as Vercel. The offline scanner still works here.";
    if (isFile) {
      label = "Local file mode";
      detail = "Local file previews cannot run /api/proxuma-rdap. Use generated lookup links or deploy through Vercel for RDAP.";
    } else if (isGithubPages) {
      label = "GitHub Pages host";
      detail = "GitHub Pages serves the static app but cannot run /api/proxuma-rdap. Deploy the same repo through Vercel for RDAP.";
    } else if (isLocalhost) {
      label = "Local development host";
      detail = "RDAP can work only if a local serverless/Vercel dev bridge is running. Otherwise use lookup links.";
    } else if (isVercel) {
      label = "Vercel/serverless host";
      detail = "This host can run the consent-gated RDAP bridge if /api/proxuma-rdap is deployed.";
    }
    return { protocol, host, origin, isFile, isGithubPages, isLocalhost, isVercel, label, detail };
  }

  function makeLocalRdapEndpoint(domain){
    const overrideBase = window.PROXUMA_RDAP_BRIDGE_BASE ? String(window.PROXUMA_RDAP_BRIDGE_BASE).replace(/\/$/, "") : "";
    const path = "/api/proxuma-rdap?domain=" + encodeURIComponent(domain || "");
    return overrideBase ? overrideBase + path : path;
  }

  function renderRdapFallback(message, detail){
    if (!els.onlineRdapResult) return;
    els.onlineRdapResult.innerHTML = "";
    [message, detail].filter(Boolean).forEach(function(row){
      const li = document.createElement("li");
      li.textContent = row;
      els.onlineRdapResult.appendChild(li);
    });
  }

  async function runConsentGatedRdapLookup(){
    const consent = readOnlineConsent();
    if (consent.status !== "armed") {
      setRdapStatus("Arm consent first", "status-low");
      if (els.copyStatus) els.copyStatus.textContent = "Arm Online Intel consent before running RDAP. No lookup was sent.";
      return;
    }
    const report = lastReport || emptyReport();
    const root = onlineSafeRoot(report);
    if (!root) {
      setRdapStatus("No domain available", "status-low");
      if (els.copyStatus) els.copyStatus.textContent = "Run a domain or URL scan first. RDAP needs a normal root domain.";
      return;
    }
    const hostContext = getRdapHostContext();
    if (!window.fetch) {
      setRdapStatus("Fetch unavailable", "status-low");
      renderRdapFallback("RDAP bridge not available here.", "This browser cannot call the RDAP bridge. Use generated lookup links instead.");
      if (els.copyStatus) els.copyStatus.textContent = "This browser cannot call the RDAP bridge. Use generated lookup links instead.";
      return;
    }
    if (hostContext.isFile || hostContext.isGithubPages) {
      setRdapStatus("Bridge not active on this host", "status-low");
      renderRdapFallback(hostContext.label + ": RDAP bridge is not active.", hostContext.detail);
      if (els.copyStatus) els.copyStatus.textContent = hostContext.detail + " No online lookup was sent from Proxuma.";
      return;
    }
    setRdapStatus("Checking RDAP…", "status-medium");
    if (els.copyStatus) els.copyStatus.textContent = "User-approved RDAP lookup started through the serverless bridge.";
    try {
      const response = await fetch(makeLocalRdapEndpoint(root), { method:"GET", headers:{ "Accept":"application/json" }, cache:"no-store" });
      const data = await response.json().catch(function(){ return null; });
      if (!response.ok || !data || !data.ok) {
        const message = data && data.error ? data.error : "RDAP bridge did not return a usable result.";
        const hostContext = getRdapHostContext();
        setRdapStatus("RDAP unavailable", "status-low");
        renderRdapFallback("RDAP bridge returned no usable result.", message + " " + hostContext.detail);
        if (els.copyStatus) els.copyStatus.textContent = message + " " + hostContext.detail;
        return;
      }
      latestRdapSummary = data.result || null;
      if (lastReport) lastReport.rdapSummary = latestRdapSummary;
      renderRdapSummary(latestRdapSummary);
      setRdapStatus("RDAP result saved", "status-medium");
      if (els.copyStatus) els.copyStatus.textContent = "RDAP result saved into the current case packet. Treat it as context, not a final safety verdict.";
    } catch(error) {
      const hostContext = getRdapHostContext();
      setRdapStatus("Bridge not reachable", "status-low");
      renderRdapFallback("RDAP bridge was not reachable.", hostContext.detail);
      if (els.copyStatus) els.copyStatus.textContent = "RDAP bridge was not reachable. " + hostContext.detail;
    }
  }

  function readOnlineFindingsNotes(){
    try {
      const parsed = JSON.parse(localStorage.getItem(ONLINE_FINDINGS_KEY) || "null");
      if (!parsed || typeof parsed !== "object") return { notes:"", updatedAt:null, target:"" };
      return {
        notes: String(parsed.notes || "").slice(0, 2000),
        updatedAt: parsed.updatedAt || null,
        target: String(parsed.target || "").slice(0, 240)
      };
    } catch(error) {
      return { notes:"", updatedAt:null, target:"" };
    }
  }

  function renderOnlineFindingsNotes(){
    const stored = readOnlineFindingsNotes();
    if (els.onlineFindingsNotes && els.onlineFindingsNotes.value !== stored.notes) els.onlineFindingsNotes.value = stored.notes;
    if (els.onlineFindingsStatus) {
      els.onlineFindingsStatus.textContent = stored.notes
        ? "Saved locally" + (stored.updatedAt ? " · " + formatCompactReportTime(new Date(stored.updatedAt)) : "")
        : "No online findings saved yet";
    }
  }

  function saveOnlineFindingsNotes(){
    const notes = els.onlineFindingsNotes ? String(els.onlineFindingsNotes.value || "").trim().slice(0, 2000) : "";
    const payload = {
      notes,
      updatedAt: notes ? new Date().toISOString() : null,
      target: lastReport && lastReport.raw ? String(lastReport.raw).slice(0, 240) : ""
    };
    try {
      if (notes) localStorage.setItem(ONLINE_FINDINGS_KEY, JSON.stringify(payload));
      else localStorage.removeItem(ONLINE_FINDINGS_KEY);
    } catch(error) {}
    if (lastReport) lastReport.onlineFindingsNotes = notes;
    renderOnlineFindingsNotes();
    if (els.copyStatus) els.copyStatus.textContent = notes ? "Online Intel findings notes saved locally. No provider was contacted." : "Online Intel notes cleared locally.";
  }

  function clearOnlineFindingsNotes(){
    try { localStorage.removeItem(ONLINE_FINDINGS_KEY); } catch(error) {}
    if (els.onlineFindingsNotes) els.onlineFindingsNotes.value = "";
    if (lastReport) lastReport.onlineFindingsNotes = "";
    renderOnlineFindingsNotes();
    if (els.copyStatus) els.copyStatus.textContent = "Online Intel findings notes cleared. No scan history was deleted.";
  }

  function currentOnlineFindingsNotes(){
    const typed = els.onlineFindingsNotes ? String(els.onlineFindingsNotes.value || "").trim() : "";
    if (typed) return typed.slice(0, 2000);
    return readOnlineFindingsNotes().notes || "";
  }

  function safePatternKey(value){
    return String(value || "unknown").toLowerCase().replace(/[^a-z0-9._-]+/g, "-").slice(0,96) || "unknown";
  }

  function patternTriggerFamily(report){
    const text = String((report && (report.primaryTrigger || report.explain || "")) || "").toLowerCase();
    if (/credential|login|password|otp|2fa|mfa|account|verify/.test(text)) return "credential-intent";
    if (/redirect|wrapper|shortener|relay|continue|return/.test(text)) return "redirect-wrapper";
    if (/download|file|extension|installer|archive/.test(text)) return "download-trap";
    if (/brand|lookalike|mismatch|institution|bank|stuffed/.test(text)) return "brand-impersonation";
    if (/qr|payload|embedded/.test(text)) return "qr-payload";
    if (/unicode|punycode|control|encoded|malformed/.test(text)) return "parser-deception";
    return report && report.risk === "Low Risk" ? "clean-structure" : "general-caution";
  }

  function applyLocalPatternMemory(report){
    if (!report || !report.raw) return report;
    const memory = readPatternMemory();
    const rootKey = safePatternKey(report.root || report.target || "unresolved");
    const family = patternTriggerFamily(report);
    const rootStats = memory.roots[rootKey] || { count:0, high:0, review:0, low:0, lastRisk:"", lastFamily:"" };
    const familyStats = memory.triggers[family] || { count:0, high:0, review:0 };
    const notes = [];
    let bump = 0;

    if ((rootStats.high + rootStats.review) >= 2 && report.risk !== "High Risk") {
      bump += 8;
      notes.push("This root has appeared in local memory with review/high-risk outcomes before.");
    } else if (rootStats.count >= 3 && report.risk !== "High Risk") {
      bump += 4;
      notes.push("This root has been scanned repeatedly on this device. Repetition is not proof of danger, but it deserves context checks.");
    }

    if (family !== "clean-structure" && familyStats.count >= 2 && report.risk !== "High Risk") {
      bump += 6;
      notes.push("This scan matches a repeated local pattern family: " + family.replace(/-/g, " ") + ".");
    }

    report.localPatternMemory = {
      status: notes.length ? "Repeated local pattern noticed" : "No repeated local pattern",
      rootSeenBefore: rootStats.count,
      patternFamily: family,
      familySeenBefore: familyStats.count,
      notes
    };

    if (notes.length) {
      report.score = Math.min(100, Math.max(0, Math.round((report.score || 0) + bump)));
      report.heatPercent = report.score;
      if (report.score >= 60) { report.risk = "High Risk"; report.riskClass = "risk-high"; report.next = "Do not enter info"; report.heatLabel = "Hot / High Risk"; }
      else if (report.score >= 20 && report.risk === "Low Risk") { report.risk = "Needs Review"; report.riskClass = "risk-medium"; report.next = "Verify first"; report.heatLabel = "Warm / Review"; }
      report.count = (report.count || 0) + 1;
      report.medium = (report.medium || 0) + 1;
      const memoryEvidence = "[MEDIUM] Local pattern memory — " + notes.join(" ") + " Pattern memory is stored only in this browser and uses roots/signal families, not full browsing history.";
      report.evidence = [memoryEvidence].concat(report.evidence || []);
      report.technical = (report.technical || []).concat([
        "v2.73 local pattern memory: compared this scan against prior on-device root and signal-family counters.",
        "v2.73 privacy boundary: memory is localStorage-only, stores compact roots/signal families/counts, and makes no network/API request."
      ]);
      report.timeline = (report.timeline || []).concat(["v2.73 checked local pattern memory before rendering the final report."]);
      report.summary = (report.summary || "") + " Local pattern memory also noticed repetition on this device, so Proxuma recommends a little extra verification.";
      report.plainVerdict = (report.plainVerdict || report.summary || "") + " Local pattern memory noticed repeated structure on this device.";
      report.quickSummary = (report.quickSummary || report.summary || "") + " Local pattern memory noticed repeated structure on this device.";
      report.primaryTrigger = "Local pattern memory + " + (report.primaryTrigger || "scan evidence");
      report.confidenceNote = (report.confidenceNote || "") + " Local memory added context from prior scans on this device only.";
      report.reportTags = Array.from(new Set((report.reportTags || []).concat(["local-pattern-memory", family])));
    } else {
      report.technical = (report.technical || []).concat(["v2.73 local pattern memory: no repeated on-device pattern affected this verdict."]);
    }
    return report;
  }

  function rememberPattern(report){
    if (!report || !report.raw) return;
    const memory = readPatternMemory();
    const rootKey = safePatternKey(report.root || report.target || "unresolved");
    const family = patternTriggerFamily(report);
    const rootStats = memory.roots[rootKey] || { count:0, high:0, review:0, low:0, lastRisk:"", lastFamily:"" };
    rootStats.count += 1;
    if (report.risk === "High Risk") rootStats.high += 1;
    else if (report.risk === "Needs Review") rootStats.review += 1;
    else rootStats.low += 1;
    rootStats.lastRisk = report.risk;
    rootStats.lastFamily = family;
    rootStats.lastSeen = new Date().toISOString();
    memory.roots[rootKey] = rootStats;

    const familyStats = memory.triggers[family] || { count:0, high:0, review:0, lastSeen:"" };
    familyStats.count += 1;
    if (report.risk === "High Risk") familyStats.high += 1;
    if (report.risk === "Needs Review") familyStats.review += 1;
    familyStats.lastSeen = new Date().toISOString();
    memory.triggers[family] = familyStats;
    memory.total = (memory.total || 0) + 1;

    // Keep the memory small and local. Remove oldest-looking roots if the counter grows too large.
    const rootEntries = Object.entries(memory.roots);
    if (rootEntries.length > 50) {
      rootEntries.sort((a,b) => String(b[1].lastSeen || "").localeCompare(String(a[1].lastSeen || "")));
      memory.roots = Object.fromEntries(rootEntries.slice(0,50));
    }
    try { localStorage.setItem(PATTERN_MEMORY_KEY, JSON.stringify(memory)); } catch {}
  }

  function makeScanComparison(report, previous){
    if (!report || !report.raw) return {memory:"No previous scan", compare:"Waiting for the first scan."};
    if (!previous || typeof previous.score !== "number") {
      return {memory:"First scan captured", compare:"This scan is now stored locally as the comparison point."};
    }
    const delta = report.score - previous.score;
    const absDelta = Math.abs(delta);
    let direction = "same risk level";
    if (delta >= 10) direction = "risk increased";
    else if (delta <= -10) direction = "risk dropped";
    else if (delta > 0) direction = "slightly higher risk";
    else if (delta < 0) direction = "slightly lower risk";

    const rootShift = previous.root && previous.root !== report.root
      ? " Root changed from " + previous.root + " to " + report.root + "."
      : " Root stayed on " + (report.root || "the same target") + ".";

    const triggerShift = previous.primaryTrigger && previous.primaryTrigger !== report.primaryTrigger
      ? " Main trigger changed from " + previous.primaryTrigger + " to " + report.primaryTrigger + "."
      : " Main trigger stayed consistent.";

    return {
      memory: "Previous: " + previous.score + "/100 · " + previous.risk,
      compare: direction.charAt(0).toUpperCase() + direction.slice(1) + " by " + absDelta + " point" + (absDelta === 1 ? "" : "s") + "." + rootShift + triggerShift
    };
  }

  function severityHtml(high, medium, low){
    return '<em class="sev-high">' + escapeHtml(high) + ' high</em>' +
           '<em class="sev-medium">' + escapeHtml(medium) + ' medium</em>' +
           '<em class="sev-low">' + escapeHtml(low) + ' low</em>';
  }



  function toneClassFromText(value){
    const text = String(value || "").toLowerCase();
    if (text.includes("high risk") || text.includes("do not") || text.includes("danger") || text.includes("high-severity") || text.includes("risky file") || text.includes("brand outside") || text.includes("deception")) return "status-high";
    if (text.includes("needs review") || text.includes("verify") || text.includes("caution") || text.includes("medium") || text.includes("pressure") || text.includes("shortener") || text.includes("review")) return "status-medium";
    if (text.includes("low risk") || text.includes("trusted") || text.includes("local only") || text.includes("clean") || text.includes("safe") || text.includes("no major")) return "status-low";
    return "";
  }

  function classifyListItem(item){
    const text = String(item || "").toLowerCase();
    if (text.includes("high") || text.includes("do not") || text.includes("risky file") || text.includes("brand outside") || text.includes("deception")) return "signal-high";
    if (text.includes("medium") || text.includes("verify") || text.includes("caution") || text.includes("pressure") || text.includes("shortener") || text.includes("review")) return "signal-medium";
    if (text.includes("trusted") || text.includes("low") || text.includes("no major") || text.includes("clean") || text.includes("safe")) return "signal-low";
    return "signal-info";
  }

  function renderList(el, items, ordered){
    if (!el) return;
    el.innerHTML = "";
    (items && items.length ? items : ["No information yet."]).forEach(item => {
      const li = document.createElement("li");
      li.textContent = item;
      li.className = classifyListItem(item);
      el.appendChild(li);
    });
  }

  function guidanceFor(report){
    if (!report || !report.raw) {
      return {
        actionTitle:"Scan first",
        actionText:"Paste a URL, domain, or decoded QR payload to receive a clear next move.",
        whyTitle:"Pattern lesson",
        whyText:"Proxuma will explain the strongest warning sign in plain language after analysis.",
        safetyTitle:"Stay aware",
        safetyText:"Never enter passwords, banking details, or verification codes unless you are certain you are on the official site."
      };
    }
    if (report.reportConsistency && report.whatToDoNext) {
      return {
        actionTitle: report.whatToDoNext.actionTitle,
        actionText: report.reportConsistency.whatToDoNext || report.whatToDoNext.actionText,
        whyTitle: report.whatToDoNext.whyTitle,
        whyText: report.reportConsistency.whyItMatters || report.whatToDoNext.whyText,
        safetyTitle: report.whatToDoNext.safetyTitle,
        safetyText: report.reportConsistency.safetyHabit || report.whatToDoNext.safetyText,
        steps: report.whatToDoNext.steps
      };
    }
    if (report.whatToDoNext) {
      return report.whatToDoNext;
    }
    if (report.risk === "High Risk") {
      return {
        actionTitle:"Stop — verify elsewhere",
        actionText:(report.userSteps && report.userSteps[0]) || "Close the page or message path. Do not enter login details, payment information, or verification codes.",
        whyTitle:"Strong warning pattern",
        whyText: report.explain || "The target combines signals commonly used in impersonation, pressure, or unsafe payloads.",
        safetyTitle:"Protect the account",
        safetyText:report.orgEscalation || "Use a saved bookmark or type the official address manually. If this came from a QR code, message, or email, treat it as suspicious."
      };
    }
    if (report.risk === "Needs Review") {
      return {
        actionTitle:"Pause — verify first",
        actionText:(report.userSteps && report.userSteps[0]) || "Do not enter sensitive information yet. Check the official source manually before continuing.",
        whyTitle:"Review signal found",
        whyText: report.explain || "The target has a pattern that deserves attention, even if it is not enough for a high-risk verdict.",
        safetyTitle:"Confirm out-of-band",
        safetyText:report.orgEscalation || "Use a known app, bookmark, or official website instead of trusting the scanned or pasted address immediately."
      };
    }
    return {
      actionTitle:"Proceed with normal caution",
      actionText:(report.userSteps && report.userSteps[0]) || "No major local warning pattern was found. Still confirm the page matches what you expected before signing in.",
      whyTitle:"Low local-risk result",
      whyText: report.explain || "The root and visible structure did not trigger major local warning signals.",
      safetyTitle:"Normal safety habit",
      safetyText:report.orgEscalation || "Low risk does not guarantee safety. Avoid entering sensitive information if the link arrived unexpectedly."
    };
  }

  function renderReport(report){
    els.riskLabel.textContent = report.risk;
    els.riskLabel.className = report.riskClass;
    els.scoreValue.textContent = (report.score === 0 || report.score) ? String(report.score) : "--";
    const numberClass = report.risk === "High Risk" ? "value-high" : (report.risk === "Needs Review" ? "value-medium" : "value-low");
    const statusClass = report.risk === "High Risk" ? "status-high" : (report.risk === "Needs Review" ? "status-medium" : "status-low");
    const reportStateClass = report.risk === "High Risk" ? "report-high" : (report.risk === "Needs Review" ? "report-medium" : "report-low");
    const reportPanel = document.querySelector(".report-panel");
    if (reportPanel) reportPanel.className = "report-panel card " + reportStateClass;
    document.documentElement.setAttribute("data-risk-state", report.risk === "High Risk" ? "high" : (report.risk === "Needs Review" ? "medium" : (report.raw ? "low" : "standby")));
    els.scoreValue.className = numberClass;
    const ring = els.scoreValue.closest ? els.scoreValue.closest(".score-ring") : null;
    if (ring) ring.className = "score-ring " + (report.risk === "High Risk" ? "ring-high" : (report.risk === "Needs Review" ? "ring-medium" : "ring-low"));
    const selectedSummary = audienceView === "analyst" ? report.summary : (report.plainVerdict || report.quickSummary || report.summary);
    els.summaryText.textContent = selectedSummary;
    els.trueTarget.textContent = report.target;
    els.trueTarget.className = numberClass;
    els.signalCount.textContent = String(report.count);
    els.signalCount.className = report.high ? "value-high" : (report.medium ? "value-medium" : "value-low");
    els.nextStep.textContent = report.next;
    els.nextStep.className = numberClass;
    if (els.severityMix) els.severityMix.innerHTML = severityHtml(report.high || 0, report.medium || 0, report.low || 0);
    if (els.severityNote) els.severityNote.textContent = report.severityNote;
    if (els.heatFill) els.heatFill.style.width = String(report.heatPercent || 0) + "%";
    if (els.heatLabel) { els.heatLabel.textContent = report.heatLabel || "Standby"; els.heatLabel.className = numberClass; }
    if (els.primaryTrigger) { els.primaryTrigger.textContent = report.primaryTrigger || "Waiting"; els.primaryTrigger.className = numberClass; }
    if (els.inputTypeLabel) { els.inputTypeLabel.textContent = report.inputType || "Standby"; els.inputTypeLabel.className = report.raw ? numberClass : ""; }
    if (els.reportTimestamp) {
      const fullTime = report.time || formatReportTime(new Date());
      els.reportTimestamp.textContent = report.raw ? (report.displayTime || formatCompactReportTime(new Date())) : "Not scanned";
      els.reportTimestamp.title = report.raw ? fullTime : "";
      els.reportTimestamp.className = report.raw ? numberClass : "";
    }

    const anatomyCard = document.querySelector(".link-anatomy-card");
    const anatomy = report.anatomy || makeLinkAnatomy(report.raw ? { type:"payload", raw:report.raw } : { type:"empty" });
    if (els.anatomyStatus) els.anatomyStatus.textContent = anatomy.status || "Waiting for input";
    if (els.anatomyProtocol) els.anatomyProtocol.textContent = anatomy.protocol || "—";
    if (els.anatomyHost) els.anatomyHost.textContent = anatomy.host || "—";
    if (els.anatomyRoot) els.anatomyRoot.textContent = anatomy.root || "—";
    if (els.anatomyPath) els.anatomyPath.textContent = anatomy.path || "—";
    if (els.anatomyQuery) els.anatomyQuery.textContent = anatomy.query || "—";
    if (els.anatomyTokens) els.anatomyTokens.textContent = anatomy.tokens || "—";

    // Keep Link Anatomy dense: short/absent values should not consume full-width cards.
    const anatomyValueState = (field, value) => {
      const row = document.querySelector(`[data-anatomy-field="${field}"]`);
      if (!row) return;
      const text = String(value || "—").trim();
      const isEmpty = text === "—" || /^No (query parameters|obvious structural risk tokens|URL query|URL tokens)$/i.test(text);
      const isLong = text.length > 46 || text.includes(", ") && text.length > 34;
      row.classList.toggle("anatomy-value-empty", isEmpty);
      row.classList.toggle("anatomy-value-long", !isEmpty && isLong);
      row.classList.toggle("anatomy-value-present", !isEmpty);
    };
    anatomyValueState("path", anatomy.path);
    anatomyValueState("query", anatomy.query);
    anatomyValueState("tokens", anatomy.tokens);
    if (els.anatomyNote) els.anatomyNote.textContent = anatomy.note || "Structure details appear after a scan.";
    if (anatomyCard) {
      anatomyCard.classList.toggle("anatomy-populated", !!report.raw);
      anatomyCard.classList.toggle("anatomy-empty", !report.raw);
    }

    if (els.copyStatus && !report.raw) els.copyStatus.textContent = "Run a scan, then copy the summary or open Export for more formats.";
    if (els.whyScore) { els.whyScore.textContent = report.whyScore || "Waiting for local evidence."; els.whyScore.className = numberClass; }
    if (els.laneQuality) { els.laneQuality.textContent = report.laneQuality || "Standby"; els.laneQuality.className = numberClass; }
    if (els.evidenceStrength) { els.evidenceStrength.textContent = report.evidenceStrength || "Waiting"; els.evidenceStrength.className = numberClass; }
    if (els.confidenceBrief) { els.confidenceBrief.textContent = report.confidenceBrief || "Waiting"; els.confidenceBrief.className = numberClass; }
    if (els.scanMemory) { els.scanMemory.textContent = report.scanMemory || "No previous scan"; els.scanMemory.className = numberClass; }
    if (els.compareLast) { els.compareLast.textContent = report.compareLast || "Waiting for the first scan."; els.compareLast.className = numberClass; }

    // RC-9 direct Supporting Evidence bridge. This visible card is updated by
    // the authoritative scan engine itself, so it does not depend on a later
    // dashboard relay or user interaction.
    (function updateVisibleSupportingEvidence(){
      const card = document.getElementById("scan-detail-workspace");
      if (!card) return;
      let high = Number(report.high || 0) || 0;
      let medium = Number(report.medium || 0) || 0;
      let low = Number(report.low || 0) || 0;
      const evidenceTotal = Array.isArray(report.evidence) ? report.evidence.filter(Boolean).length : 0;
      const score = Number(report.score || 0) || 0;
      const total = Math.max(Number(report.count || 0) || 0, evidenceTotal, score > 0 ? 1 : 0);
      const suppliedClassifiedTotal = high + medium + low;
      let unclassified = Math.max(Number(report.unclassified || 0) || 0, total - suppliedClassifiedTotal, 0);
      // Conservative fallback for reports without genuine severity buckets:
      // classify the leading signal only and preserve the remainder as
      // unclassified. Overall risk is not a per-signal severity label.
      if (suppliedClassifiedTotal === 0 && total > 0) {
        if (report.risk === "High Risk" || score >= 70) high = 1;
        else if (report.risk === "Needs Review" || score >= 35) medium = 1;
        else low = 1;
        unclassified = Math.max(total - 1, 0);
      }
      const mix = card.querySelector(".severity-breakdown");
      if (mix) {
        mix.innerHTML = `<em class="sev-high">${high} high</em> <em class="sev-medium">${medium} medium</em> <em class="sev-low">${low} low</em>${unclassified ? ` <em class="sev-unclassified">${unclassified} unclassified</em>` : ""}`;
        mix.setAttribute("aria-label", `${high} high, ${medium} medium, ${low} low${unclassified ? `, ${unclassified} unclassified` : ""} signals`);
      }
      const strength = document.getElementById("evidenceStrength");
      if (strength) {
        strength.textContent = report.evidenceStrength || makeEvidenceStrength(Number(report.score || 0), high, medium, low, report.target) || "Evidence available";
        strength.className = numberClass;
      }
      const memory = document.getElementById("scanMemory");
      if (memory) {
        memory.textContent = report.scanMemory || "No previous scan";
        memory.className = numberClass;
      }
      const list = document.getElementById("visibleEvidenceList");
      if (list) {
        const evidence = Array.isArray(report.evidence) ? report.evidence.filter(Boolean) : [];
        list.innerHTML = (evidence.length ? evidence : ["No supporting evidence was returned for this scan."])
          .map(item => `<li>${escapeHtml(String(item))}</li>`).join("");
      }
    })();
    renderPatternMemoryDashboard();
    const heatBar = document.querySelector(".heat-bar");
    if (heatBar) heatBar.setAttribute("aria-valuenow", String(report.heatPercent || 0));

    // RC-4 compatibility fuse: these legacy fields are optional in the compact dashboard.
    // Never allow a missing presentation-only element to abort the scan render before
    // Analysis View, evidence, timeline, and action panels receive their data.
    if (els.scanMode) {
      els.scanMode.textContent = report.scanMode;
      els.scanMode.className = report.raw && report.scanMode === "Payload lane" ? "value-medium" : "value-low";
    }
    if (els.scanModeNote) {
      els.scanModeNote.textContent = report.raw ? (audienceView === "analyst" ? "Analyst View is showing deeper local evidence. No external request was made." : "User View is showing the safest plain-language read. Analysis stayed local on this device.") : "Waiting for a target.";
    }
    els.rootDomain.textContent = report.root;
    els.rootDomainNote.textContent = report.raw ? "True target extracted from the submitted input." : "The root is the part attackers try to hide.";
    els.confidenceLabel.textContent = report.confidence;
    els.confidenceLabel.className = report.risk === "Needs Review" ? "value-medium" : numberClass;
    els.confidenceNote.textContent = report.confidenceNote;
    els.safeMove.textContent = report.next;
    els.safeMoveNote.textContent = report.summary;

    els.explainStatus.textContent = report.risk;
    els.explainStatus.className = "status-pill " + statusClass;
    els.explainSummary.textContent = report.explain;
    els.explainSummary.className = "card-summary " + statusClass;
    els.trustStatus.textContent = "Local only";
    els.trustStatus.className = "status-low";
    els.threatStatus.textContent = report.risk;
    els.threatStatus.className = "status-pill " + statusClass;
    els.threatStory.textContent = report.threat;
    els.threatStory.className = "card-summary " + statusClass;
    els.timelineStatus.textContent = report.timeline.length + " steps";
    els.timelineStatus.className = "status-pill status-low";
    els.learningStatus.textContent = report.raw ? "Scan takeaway" : "Ready after scan";
    els.learningStatus.className = "status-pill status-low";
    els.learningText.textContent = report.learning;
    renderOnlineConsentPanel(report);
    if (els.decisionStatus) { els.decisionStatus.textContent = report.risk; els.decisionStatus.className = "status-pill " + statusClass; }

    renderList(els.evidenceList, report.evidence);
    renderList(els.technicalList, report.technical);
    renderList(els.trustTrail, report.trust);
    renderList(els.timelineList, report.timeline, true);
    renderList(els.decisionList, audienceView === "analyst" ? report.decision : (report.userSteps || report.decision), true);
    if (els.analystBriefList) renderList(els.analystBriefList, audienceView === "analyst" ? (report.analystBrief || report.technical || []) : (report.userBrief || report.userSteps || []));
    if (els.analystBriefStatus) { els.analystBriefStatus.textContent = audienceView === "analyst" ? (report.triagePriority || "Analyst triage") : "User safety brief"; els.analystBriefStatus.className = "status-pill " + statusClass; }

    const guidance = guidanceFor(report);
    if (els.actionTitle) { els.actionTitle.textContent = guidance.actionTitle; els.actionTitle.className = numberClass; }
    if (els.actionText) els.actionText.textContent = guidance.actionText;
    if (els.whyMatterTitle) { els.whyMatterTitle.textContent = guidance.whyTitle; els.whyMatterTitle.className = numberClass; }
    if (els.whyMatterText) els.whyMatterText.textContent = guidance.whyText;
    if (els.safetyTitle) { els.safetyTitle.textContent = guidance.safetyTitle; els.safetyTitle.className = numberClass; }
    if (els.safetyText) els.safetyText.textContent = guidance.safetyText;
  }

  function buildUserReportText(report){
    if (!report || !report.raw) return "No Proxuma IT scan has been run yet.";
    return [
      "Proxuma IT User View",
      "Build: " + BUILD.version + " — " + BUILD.name,
      "Time: " + (report.time || formatReportTime(new Date())),
      "Risk: " + report.risk + " (" + report.score + "/100)",
      "Plain-Language Verdict: " + (report.plainVerdict || report.summary),
      "What Happened: " + (report.whatHappened || report.summary),
      "Why It Matters: " + (report.reportWhyItMatters || report.whyThisMatters || report.explain || "No additional explanation."),
      "What To Do Next: " + (report.reportWhatToDoNext || report.next),
      "Safety Habit: " + (report.safetyHabit || "Use official routes for sensitive action."),
      "Threat Lane: " + ((report.threatLaneId || "LANE-NONE-000") + " / " + (report.threatLaneReportName || report.threatLaneLabel || "No dominant lane")),
      "User Safety Brief:",
      ...((report.userBrief || []).map(item => "- " + item)),
      "Main Reason: " + ((report.primaryReason && report.primaryReason[0]) || report.primaryTrigger || report.explain || "No single trigger"),
      "Safe Next Move: " + report.next,
      "User Steps:",
      ...((report.userSteps || report.decision || []).map(item => "- " + item)),
      "Local Pattern Memory: " + ((report.localPatternMemory && report.localPatternMemory.status) || "No repeated local pattern"),
      ...(((report.localPatternMemory && report.localPatternMemory.notes) || []).map(item => "- " + item)),
      "Target Checked: " + report.raw,
      "Resolved Root: " + report.root,
      "Offline note: This user-facing report was generated locally. No API, CDN, telemetry, or live reputation check was used."
    ].join("\n");
  }

  function buildFullReportText(report){
    if (!report || !report.raw) return "No Proxuma IT scan has been run yet.";
    return [
      "Proxuma IT Report",
      "Build: " + BUILD.version + " — " + BUILD.name,
      "Time: " + (report.time || formatReportTime(new Date())),
      "Input Type: " + (report.inputType || "Unknown"),
      "Target: " + report.raw,
      "Resolved Target: " + report.target,
      "Root Domain: " + report.root,
      "Risk: " + report.risk + " (" + report.score + "/100)",
      "Primary Trigger: " + (report.primaryTrigger || "None"),
      "Selected View: " + (audienceView === "analyst" ? "Analyst View" : "User View"),
      "Audience Mode: " + (report.audienceMode || "General user"),
      "Next Move: " + report.next,
      "Quick Summary: " + (report.quickSummary || report.summary),
      "Plain-Language Verdict: " + (report.plainVerdict || report.summary),
      "What Happened: " + (report.whatHappened || report.summary),
      "Why This Matters: " + (report.reportWhyItMatters || report.whyThisMatters || report.explain || "No additional explanation."),
      "What To Do Next: " + (report.reportWhatToDoNext || report.next),
      "Safety Habit: " + (report.safetyHabit || "Use official routes for sensitive action."),
      "Threat Lane: " + ((report.threatLaneId || "LANE-NONE-000") + " / " + (report.threatLaneReportName || report.threatLaneLabel || "No dominant lane")),
      "Report Consistency Checklist:",
      ...((report.reportChecklist || []).map(item => "- " + item)),
      "Primary Reason:",
      ...((report.primaryReason || [report.primaryTrigger || "None"]).map(item => "- " + item)),
      "Supporting Evidence:",
      ...((report.supportingEvidence || []).map(item => "- " + item)),
      "Lower-Weight Clues:",
      ...((report.lowerWeightClues || []).map(item => "- " + item)),
      "Trust Relief / Why It Was Not Worse:",
      ...((report.trustReliefNotes || []).map(item => "- " + item)),
      "Report Tags: " + ((report.reportTags || []).join(", ") || "none"),
      "Local Pattern Memory: " + ((report.localPatternMemory && report.localPatternMemory.status) || "No repeated local pattern"),
      ...(((report.localPatternMemory && report.localPatternMemory.notes) || []).map(item => "- " + item)),
      "Case Packet ID: " + (report.casePacketId || "not generated"),
      "Case Reference: " + (report.caseReference || "not generated"),
      "Evidence Digest: " + (report.evidenceDigest || "not generated"),
      "Export Envelope: v3.14 local JSON evidence packet with offline integrity seal available through Download JSON.",
      "Professional Summary:",
      report.caseProfessionalSummary || buildCleanSummaryText(report),
      "Case Packet Summary:",
      ...((report.casePacketSummary || []).map(item => "- " + item)),
      "Evidence Chain:",
      ...((report.casePacketChain || []).map(item => "- " + item)),
      "Preservation Checklist:",
      ...((report.preservationChecklist || []).map(item => "- " + item)),
      "Analyst Brief:",
      ...((report.analystBrief || []).map(item => "- " + item)),
      "User Safety Brief:",
      ...((report.userBrief || []).map(item => "- " + item)),
      "User Steps:",
      ...((report.userSteps || []).map(item => "- " + item)),
      "Organization / Team Escalation:",
      "- " + (report.orgEscalation || "No escalation guidance generated."),
      "Evidence:",
      ...(report.evidence || []).map(item => "- " + item),
      "Decision Guide:",
      ...(report.decision || []).map(item => "- " + item),
      "Offline note: This report was generated locally. No API, CDN, telemetry, or live reputation check was used."
    ].join("\n");
  }

  function buildProfessionalSummaryText(report){
    if (!report || !report.raw) return "No Proxuma IT scan has been run yet.";
    return report.caseProfessionalSummary || [
      "Proxuma IT reviewed this target locally.",
      "Case: " + (report.caseReference || report.casePacketId || "not generated") + ".",
      "Verdict: " + report.risk + " (" + report.score + "/100).",
      "Root: " + report.root + ".",
      "Primary evidence: " + ((report.primaryReason && report.primaryReason[0]) || report.primaryTrigger || "No single trigger") + ".",
      "Recommendation: " + report.next + "."
    ].join(" ");
  }

  function stableCaseStringify(value){
    if (value === null || typeof value !== "object") return JSON.stringify(value);
    if (Array.isArray(value)) return "[" + value.map(stableCaseStringify).join(",") + "]";
    return "{" + Object.keys(value).sort().map(key => JSON.stringify(key) + ":" + stableCaseStringify(value[key])).join(",") + "}";
  }

  function makeOfflineIntegritySeal(value){
    const text = stableCaseStringify(value || {});
    let hash = 2166136261;
    for (let i = 0; i < text.length; i += 1) {
      hash ^= text.charCodeAt(i);
      hash = Math.imul(hash, 16777619) >>> 0;
    }
    const hex = ("00000000" + hash.toString(16)).slice(-8);
    return "PX-LOCAL-" + hex.toUpperCase();
  }

  function buildExportEnvelope(report, packetCore){
    const core = packetCore || {};
    const sealSource = {
      build: core.build,
      case: core.case,
      target: core.target,
      verdict: core.verdict,
      evidenceDigest: core.evidence && core.evidence.digest,
      localDigest: core.evidence && core.evidence.localDigest
    };
    const seal = makeOfflineIntegritySeal(sealSource);
    return {
      schema: "proxuma-it.case-packet.v3.14",
      offlineIntegritySeal: seal,
      generatedBy: "Proxuma IT local browser engine",
      exportType: "Local JSON evidence packet",
      privacyBoundary: "Offline export only. No lookup, fetch, telemetry, or background network action was required to generate this packet.",
      verificationHints: [
        "Confirm the build version shown in the app matches this packet.",
        "Confirm the scanned target, root domain, case reference, evidence digest, and offline integrity seal match the saved case.",
        "Treat this packet as a local triage aid, not as proof that a website is safe or malicious by itself.",
        "For banking, government, school, shipping, or employment issues, verify through the official website/app/phone number you already trust."
      ],
      preservationSteps: [
        "Save the JSON file without editing it.",
        "Keep the original message, email, QR screenshot, or URL beside the packet.",
        "Do not enter passwords, codes, seed phrases, payment details, or ID numbers into the scanned target.",
        "If money, identity, or workplace access is involved, escalate through a trusted official channel before acting."
      ]
    };
  }

  function buildCasePacketJson(report){
    if (!report || !report.raw) return null;
    const packet = {
      product: "Proxuma IT",
      build: { version: BUILD.version, name: BUILD.name, privacy: BUILD.privacy },
      case: { id: report.casePacketId || "not generated", reference: report.caseReference || "not generated", created: report.time || formatReportTime(new Date()), inputType: report.inputType || "Unknown", selectedView: audienceView === "analyst" ? "Analyst View" : "User View" },
      target: { raw: report.raw, resolvedTarget: report.target, rootDomain: report.root },
      verdict: { risk: report.risk, riskScore: report.score, nextMove: report.next, confidence: report.confidence, primaryTrigger: report.primaryTrigger, threatLaneId: report.threatLaneId || "LANE-NONE-000", threatLane: report.threatLaneReportName || report.threatLaneLabel || "No dominant lane" },
      summary: { professional: buildProfessionalSummaryText(report), quick: report.quickSummary || report.summary, plainLanguage: report.plainVerdict || report.summary, whatHappened: report.whatHappened || report.summary, whyThisMatters: report.reportWhyItMatters || report.whyThisMatters || report.explain, whatToDoNext: report.reportWhatToDoNext || report.next, safetyHabit: report.safetyHabit || "Use official routes for sensitive action." },
      reportConsistency: report.reportConsistency || {},
      evidence: { counts: report.evidenceCounts || {}, digest: report.evidenceDigest || "not generated", localDigest: report.localDigest || "not generated", primaryReason: report.primaryReason || [], supporting: report.supportingEvidence || [], lowerWeight: report.lowerWeightClues || [], trustRelief: report.trustReliefNotes || [], fullEvidence: report.evidence || [] },
      localPatternMemory: report.localPatternMemory || { status: "No repeated local pattern" },
      onlineIntelFindings: { source: "user-entered notes from consent-opened external lookups", notes: report.onlineFindingsNotes || currentOnlineFindingsNotes() || "", privacy: "Stored locally only; Proxuma does not verify notes automatically." },
      onlineRdapResult: { source: "user-clicked consent-gated Vercel RDAP bridge", result: report.rdapSummary || latestRdapSummary || null, privacy: "RDAP lookup runs only when the user arms Online Intel and clicks Run RDAP Lookup. No automatic or hidden lookup is performed." },
      chain: report.casePacketChain || [],
      preservationChecklist: report.preservationChecklist || [],
      guidance: { userSteps: report.userSteps || [], decisionGuide: report.decision || [], organizationEscalation: report.orgEscalation || "" },
      privacy: "Generated locally from visible input structure. No threat-intel API, telemetry, or hidden online expansion was used for this verdict."
    };
    packet.exportEnvelope = buildExportEnvelope(report, packet);
    packet.offlineIntegritySeal = packet.exportEnvelope.offlineIntegritySeal;
    packet.verificationHints = packet.exportEnvelope.verificationHints;
    packet.preservationSteps = packet.exportEnvelope.preservationSteps;
    return packet;
  }

  function buildCleanSummaryText(report){
    if (!report || !report.raw) return "No Proxuma IT scan has been run yet.";
    return (report.reportOneLine || ("Proxuma IT marked this as " + report.risk + " with a risk score of " + report.score + "/100.")) + " " +
      "Main reason: " + ((report.primaryReason && report.primaryReason[0]) || report.primaryTrigger || report.explain || "No single trigger") + ". " +
      "What to do next: " + (report.reportWhatToDoNext || report.next) + ". " +
      "Safety habit: " + (report.safetyHabit || "Use official routes for sensitive action.") + ". Target checked: " + report.raw;
  }

  function copyText(text, label){
    const done = () => { if (els.copyStatus) els.copyStatus.textContent = label + " copied."; };
    const fail = () => { if (els.copyStatus) els.copyStatus.textContent = "Copy failed. Select the report text manually if needed."; };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done).catch(() => {
        try {
          const area = document.createElement("textarea");
          area.value = text;
          area.setAttribute("readonly", "");
          area.style.position = "fixed";
          area.style.left = "-9999px";
          document.body.appendChild(area);
          area.select();
          document.execCommand("copy") ? done() : fail();
          document.body.removeChild(area);
        } catch(error) { fail(); }
      });
      return;
    }
    try {
      const area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.left = "-9999px";
      document.body.appendChild(area);
      area.select();
      document.execCommand("copy") ? done() : fail();
      document.body.removeChild(area);
    } catch(error) { fail(); }
  }

  function copyFullReport(){
    if (!lastReport || !lastReport.raw) { if (els.copyStatus) els.copyStatus.textContent = "Run a scan before copying a report."; return; }
    const text = audienceView === "analyst" ? buildFullReportText(lastReport) : buildUserReportText(lastReport);
    copyText(text, audienceView === "analyst" ? "Analyst report" : "User report");
  }

  function copyCleanSummary(){
    if (!lastReport || !lastReport.raw) { if (els.copyStatus) els.copyStatus.textContent = "Run a scan before copying a summary."; return; }
    copyText(buildCleanSummaryText(lastReport), "Clean summary");
  }

  function copyCasePacket(){
    if (!lastReport || !lastReport.raw) { if (els.copyStatus) els.copyStatus.textContent = "Run a scan before copying a case packet."; return; }
    const packet = buildCasePacketJson(lastReport);
    copyText(buildProfessionalSummaryText(lastReport) + "\n\n" + JSON.stringify(packet, null, 2), "Case packet");
  }

  function buildCasePacketText(report){
    if (!report || !report.raw) return "No Proxuma IT scan has been run yet.";
    const packet = buildCasePacketJson(report);
    const seal = packet && (packet.offlineIntegritySeal || (packet.exportEnvelope && packet.exportEnvelope.offlineIntegritySeal));
    return [
      "PROXUMA IT CASE PACKET",
      "Readable TXT Export",
      "Build: " + BUILD.version + " — " + BUILD.name,
      "Generated: " + (report.time || formatReportTime(new Date())),
      "Case Reference: " + (report.caseReference || report.casePacketId || "not generated"),
      "Offline Integrity Seal: " + (seal || "not generated"),
      "",
      "VERDICT",
      "Risk: " + report.risk + " (" + report.score + "/100)",
      "Input Type: " + (report.inputType || "Unknown"),
      "Primary Trigger: " + (report.primaryTrigger || "None"),
      "Threat Lane: " + ((report.threatLaneId || "LANE-NONE-000") + " / " + (report.threatLaneReportName || report.threatLaneLabel || "No dominant lane")),
      "Next Move: " + report.next,
      "",
      "TARGET",
      "Raw Input: " + report.raw,
      "Resolved Target: " + report.target,
      "Root Domain: " + report.root,
      "",
      "PLAIN-LANGUAGE SUMMARY",
      report.plainVerdict || report.summary || "No summary generated.",
      "",
      "WHAT HAPPENED",
      report.whatHappened || report.summary || "No additional explanation generated.",
      "",
      "WHY THIS MATTERS",
      report.reportWhyItMatters || report.whyThisMatters || report.explain || "No additional explanation generated.",
      "",
      "WHAT TO DO NEXT",
      report.reportWhatToDoNext || report.next || "Use official routes before acting.",
      "",
      "PRIMARY REASON",
      ...((report.primaryReason || [report.primaryTrigger || "None"]).map(item => "- " + item)),
      "",
      "SUPPORTING EVIDENCE",
      ...((report.supportingEvidence || report.evidence || []).map(item => "- " + item)),
      "",
      "TRUST RELIEF / WHY IT WAS NOT WORSE",
      ...((report.trustReliefNotes || ["No trust-relief note generated."]).map(item => "- " + item)),
      "",
      "USER STEPS",
      ...((report.userSteps || report.decision || []).map(item => "- " + item)),
      "",
      "PRESERVATION CHECKLIST",
      ...((report.preservationChecklist || [
        "Save this report beside the original message, URL, QR screenshot, or email.",
        "Do not enter passwords, codes, seed phrases, payment details, or identity information into the scanned target.",
        "Verify through the official website, app, or phone number you already trust."
      ]).map(item => "- " + item)),
      "",
      "ONLINE INTEL FINDINGS NOTES",
      (report.onlineFindingsNotes || currentOnlineFindingsNotes() || "No user-entered online findings notes saved."),
      "",
      "CONSENT-GATED RDAP RESULT",
      (function(){ const r = report.rdapSummary || latestRdapSummary; return r ? ["Domain: " + (r.domain || "unknown"), "Registrar: " + (r.registrarName || "not shown"), "Created: " + (r.created || "not shown"), "Updated: " + (r.updated || "not shown"), "Expires: " + (r.expires || "not shown")].join("\n") : "No RDAP result saved."; })(),
      "",
      "LOCAL PRIVACY BOUNDARY",
      "This readable case packet was generated locally in the browser. No API call, telemetry, hidden lookup, live reputation check, or online expansion was required.",
      "",
      "JSON NOTE",
      "Use Download JSON for structured evidence import or future Proxuma tools. Use this TXT export for readable sharing and record keeping."
    ].join("\n");
  }

  function downloadCaseText(){
    if (!lastReport || !lastReport.raw) { if (els.copyStatus) els.copyStatus.textContent = "Run a scan before downloading a readable case report."; return; }
    const packet = buildCasePacketJson(lastReport);
    const text = buildCasePacketText(lastReport);
    try {
      const blob = new Blob([text], {type:"text/plain"});
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = ((packet && packet.case && (packet.case.reference || packet.case.id)) || "proxuma-case") + ".txt";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      if (els.copyStatus) els.copyStatus.textContent = "Readable TXT case report downloaded.";
    } catch(error) {
      copyText(text, "Readable case report fallback");
    }
  }

  function downloadCasePacket(){
    if (!lastReport || !lastReport.raw) { if (els.copyStatus) els.copyStatus.textContent = "Run a scan before downloading a case packet."; return; }
    const packet = buildCasePacketJson(lastReport);
    const text = JSON.stringify(packet, null, 2);
    try {
      const blob = new Blob([text], {type:"application/json"});
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = (packet.case.reference || packet.case.id || "proxuma-case") + ".json";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      if (els.copyStatus) els.copyStatus.textContent = "Case JSON downloaded.";
    } catch(error) {
      copyText(text, "Case JSON fallback");
    }
  }


  function explainVerdict(){
    if (!lastReport || !lastReport.raw) { if (els.copyStatus) els.copyStatus.textContent = "Run a scan first, then Proxuma can explain the verdict in plain language."; return; }
    const explanation = buildCleanSummaryText(lastReport);
    if (els.copyStatus) els.copyStatus.textContent = explanation;
    const explainCard = document.getElementById("explainSummary");
    if (explainCard && explainCard.scrollIntoView) explainCard.scrollIntoView({behavior:"smooth", block:"center"});
  }

  function setAudienceView(view, persist){
    audienceView = view === "analyst" ? "analyst" : "user";
    document.documentElement.setAttribute("data-audience-view", audienceView);
    if (els.userViewButton && els.userViewButton.classList) {
      const active = audienceView === "user";
      els.userViewButton.classList.toggle("active", active);
      els.userViewButton.setAttribute("aria-pressed", active ? "true" : "false");
    }
    if (els.analystViewButton && els.analystViewButton.classList) {
      const active = audienceView === "analyst";
      els.analystViewButton.classList.toggle("active", active);
      els.analystViewButton.setAttribute("aria-pressed", active ? "true" : "false");
    }
    if (els.activeAudienceMode) els.activeAudienceMode.textContent = audienceView === "analyst" ? "Analyst View" : "User View";
    if (els.reportDepthNote) els.reportDepthNote.textContent = audienceView === "analyst" ? "Deeper evidence, technical notes, and escalation context." : "Plain-language verdict and next move first.";
    if (persist !== false) {
      try { localStorage.setItem("proxuma-it-audience-view-v1", audienceView); } catch(error) {}
    }
    const activeTechnical = document.querySelector('.drawer-tab.active[data-drawer-target="technicalPanel"]');
    const explainTab = document.querySelector('.drawer-tab[data-drawer-target="explainPanel"]');
    if (audienceView === "user" && activeTechnical && explainTab && typeof explainTab.click === "function") explainTab.click();
    if (lastReport) renderReport(lastReport);
  }


  function detectInputKindPreview(value){
    const text = String(value || "").trim();
    if (!text) return "waiting for input";
    if (/^(javascript|data|file|vbscript|blob|about|content):/i.test(text)) return "script or local scheme";
    if (/^https?:\/\//i.test(text) || /^hxxps?:\/\//i.test(text) || /^www\./i.test(text)) return "URL";
    if (/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?:\/.*)?$/i.test(text)) return "domain";
    if (/^(wifi:|mailto:|sms:|smsto:|tel:|geo:|otpauth:|begin:vcard)/i.test(text)) return "structured QR payload";
    if (/<(?:a|form|meta|script)\b|window\.location|document\.location/i.test(text)) return "email or HTML";
    if (/%(?:25)?[0-9a-f]{2}/i.test(text) && /https?|login|verify|account/i.test(text)) return "encoded message or URL";
    if (/\b(?:dear|urgent|verify|account|payment|delivery|refund|password|code|click|call)\b/i.test(text)) return "message";
    if (/^\d{6,}$/.test(text)) return "numeric QR or reference";
    return text.length > 80 ? "text snippet" : "text";
  }

  function updateDetectedInputType(){
    if (!els.detectedInputType || !els.input) return;
    els.detectedInputType.textContent = "Detected: " + detectInputKindPreview(els.input.value);
  }

  function setQrStatus(message){
    if (els.qrStatus) els.qrStatus.textContent = message;
  }

  function stopQrScanner(){
    qrScanLoopActive = false;
    if (qrStream) {
      qrStream.getTracks().forEach(track => track.stop());
      qrStream = null;
    }
    if (els.qrVideo) els.qrVideo.srcObject = null;
    if (els.qrCameraPanel) els.qrCameraPanel.hidden = true;
    if (els.qrStopButton) els.qrStopButton.hidden = true;
    if (els.qrStartButton) els.qrStartButton.disabled = false;
    setQrStatus("Camera stopped. No camera stream remains active. Paste QR text or start the scanner again.");
  }

  function submitQrValue(value){
    const clean = (value || "").trim();
    if (!clean) return false;
    els.input.value = clean;
    setQrStatus("QR decoded locally. The payload was loaded into the scanner and analyzed on this device.");
    stopQrScanner();
    window.ProxumaPendingScanSource = "qr-scanner";
    runScan("qr-scanner");
    return true;
  }

  function ensureQrCanvas(){
    if (!qrCanvas) {
      qrCanvas = document.createElement("canvas");
      qrCanvasContext = qrCanvas.getContext("2d", { willReadFrequently: true });
    }
    return !!qrCanvasContext;
  }

  function isLocalQrDecoderReady(){
    return !!(window.jsQR && window.ProxumaLocalQrDecoder && window.ProxumaLocalQrDecoder.available === true);
  }

  function loadJsQrCompatibilityDecoder(){
    return new Promise((resolve, reject) => {
      if (isLocalQrDecoderReady()) { resolve(true); return; }
      const existing = document.querySelector('script[data-proxuma-jsqr="true"]');
      if (existing) {
        existing.addEventListener("load", () => resolve(isLocalQrDecoderReady()), { once:true });
        existing.addEventListener("error", reject, { once:true });
        return;
      }
      const script = document.createElement("script");
      script.src = "assets/vendor/jsQR.js";
      script.async = true;
      script.defer = true;
      script.setAttribute("data-proxuma-jsqr", "true");
      script.setAttribute("data-proxuma-local-decoder", "packaged");
      script.onload = () => {
        if (isLocalQrDecoderReady()) { resolve(true); return; }
        reject(new Error("Packaged local jsQR decoder loaded but did not expose a ready decoder function."));
      };
      script.onerror = () => reject(new Error("Local QR compatibility decoder failed to load from assets/vendor/jsQR.js"));
      document.head.appendChild(script);
    });
  }

  async function scanQrFrame(){
    if (!qrScanLoopActive || !els.qrVideo) return;
    try {
      if (els.qrVideo.readyState >= 2) {
        if (qrDecoderMode === "native" && qrDetector) {
          const codes = await qrDetector.detect(els.qrVideo);
          if (codes && codes.length && submitQrValue(codes[0].rawValue)) return;
        } else if (qrDecoderMode === "jsqr" && isLocalQrDecoderReady() && ensureQrCanvas()) {
          const width = els.qrVideo.videoWidth || 0;
          const height = els.qrVideo.videoHeight || 0;
          if (width && height) {
            qrCanvas.width = width;
            qrCanvas.height = height;
            qrCanvasContext.drawImage(els.qrVideo, 0, 0, width, height);
            const imageData = qrCanvasContext.getImageData(0, 0, width, height);
            const code = window.jsQR(imageData.data, width, height, { inversionAttempts: "dontInvert" });
            if (code && submitQrValue(code.data)) return;
          }
        }
      }
    } catch(error) {
      setQrStatus("Camera is open, but this browser could not read the QR frame yet. Keep the code centered, increase light, or paste the payload manually.");
    }
    if (qrScanLoopActive) window.requestAnimationFrame(scanQrFrame);
  }

  async function startQrScanner(){
    if (!els.qrStartButton || !els.qrVideo) return;
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      setQrStatus("Camera access is unavailable in this browser/context. Paste decoded QR text manually.");
      return;
    }
    try {
      els.qrStartButton.disabled = true;
      qrDetector = null;
      qrDecoderMode = "native";
      if ("BarcodeDetector" in window) {
        setQrStatus("Requesting camera permission. Proxuma stays local and uses the browser QR detector when available.");
        qrDetector = new BarcodeDetector({ formats: ["qr_code"] });
      } else {
        qrDecoderMode = "jsqr";
        setQrStatus("This browser lacks native QR detection. Proxuma is loading the packaged local jsQR decoder. Camera processing stays on this device.");
        await loadJsQrCompatibilityDecoder();
        if (!isLocalQrDecoderReady()) throw new Error("Packaged local QR decoder failed readiness check");
      }
      qrStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" }, audio: false });
      els.qrVideo.srcObject = qrStream;
      if (els.qrCameraPanel) els.qrCameraPanel.hidden = false;
      if (els.qrStopButton) els.qrStopButton.hidden = false;
      await els.qrVideo.play();
      qrScanLoopActive = true;
      setQrStatus(qrDecoderMode === "jsqr" ? "Camera active with local compatibility decoder. Center a QR code in the frame; Proxuma will scan locally in the browser." : "Camera active locally. Center a QR code in the frame; Proxuma will scan the decoded payload offline.");
      window.requestAnimationFrame(scanQrFrame);
    } catch(error) {
      stopQrScanner();
      setQrStatus("QR camera access was blocked or unavailable in this browser/context. The local decoder is embedded; you can also paste QR text manually.");
    }
  }




  function runScan(source){
    const scanSource = (typeof source === "string" && source) || window.ProxumaPendingScanSource || "analyze-button";
    window.ProxumaPendingScanSource = "";
    const previousScan = readLastScan();
    lastReport = analyze(els.input.value);
    lastReport = applyLocalPatternMemory(lastReport);
    const comparison = makeScanComparison(lastReport, previousScan);
    lastReport.scanMemory = comparison.memory;
    lastReport.compareLast = comparison.compare;
    lastReport.onlineFindingsNotes = currentOnlineFindingsNotes();
    renderReport(lastReport);
    writeLastScan(lastReport);
    rememberPattern(lastReport);
    addScanToHistory(lastReport, "auto");

    // RC-2: publish one authoritative completion signal only after the legacy
    // engine has finished rendering and persisting the complete report.
    // Every dashboard surface can now refresh from the same completed scan.
    window.ProxumaLegacyLastReport = lastReport;
    const activeFoundationState = window.ProxumaScanState?.getState?.();
    const completedDetail = {
      report: lastReport,
      source: scanSource,
      scanId: activeFoundationState?.scanId || null,
      completedAt: new Date().toISOString()
    };
    document.dispatchEvent(new CustomEvent("proxuma:legacy-scan-complete", { detail: completedDetail }));
    // Direct integration hook: avoids timing/order differences between browsers.
    if (typeof window.ProxumaApplyLegacyScanReport === "function") {
      try { window.ProxumaApplyLegacyScanReport(lastReport, scanSource); } catch (error) { console.error("Dashboard sync hook failed", error); }
    }
  }

  window.ProxumaRunLocalScan = runScan;
  window.ProxumaGetLastReport = () => lastReport;
  window.ProxumaStartQrScanner = startQrScanner;
  window.ProxumaStopQrScanner = stopQrScanner;
  window.ProxumaSaveCurrentCase = saveCase;
  window.ProxumaGetSavedCases = () => readHistory();
  window.ProxumaDownloadCaseText = downloadCaseText;
  window.ProxumaDownloadCasePacket = downloadCasePacket;
  window.ProxumaBuildCasePacketJson = report => buildCasePacketJson(report || lastReport);

  function readHistory(){
    try {
      const parsed = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
      return Array.isArray(parsed) ? parsed : [];
    } catch(error) { return []; }
  }

  function writeHistory(items){
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify((items || []).slice(0,12)));
      return true;
    } catch(error) {
      if (els.historyStatus) els.historyStatus.textContent = "Local history could not be saved. Browser storage may be blocked.";
      return false;
    }
  }

  function makeHistoryItem(report, notes, source){
    return {
      id: (report.caseReference || report.casePacketId || ("proxuma-history-" + Date.now())),
      risk: report.risk,
      score: report.score,
      inputType: report.inputType || "Unknown",
      primaryTrigger: report.primaryTrigger || "None",
      threatLane: report.threatLaneReportName || report.threatLaneLabel || "No dominant lane",
      next: report.reportWhatToDoNext || report.next || "Use official routes before acting.",
      casePacketId: report.casePacketId,
      caseReference: report.caseReference,
      evidenceDigest: report.evidenceDigest,
      target: report.raw,
      root: report.root,
      time: report.time || formatReportTime(new Date()),
      notes: (notes || "").trim(),
      onlineFindingsNotes: report.onlineFindingsNotes || currentOnlineFindingsNotes() || "",
      rdapSummary: report.rdapSummary || latestRdapSummary || null,
      source: source || "auto",
      evidence: (report.evidence || report.supportingEvidence || []).slice(0,5)
    };
  }

  function addScanToHistory(report, source){
    if (!report || !report.raw) return;
    const items = readHistory().filter(item => item && item.target !== report.raw);
    const notes = source === "manual" && els.caseNotes ? els.caseNotes.value : "";
    items.unshift(makeHistoryItem(report, notes, source));
    writeHistory(items);
    renderHistory();
  }

  function buildHistoryText(item){
    if (!item) return "No local scan history item selected.";
    return [
      "PROXUMA IT LOCAL SCAN HISTORY ITEM",
      "Stored locally on this device only",
      "Time: " + (item.time || "Unknown"),
      "Input Type: " + (item.inputType || "Unknown"),
      "Risk: " + (item.risk || "Unknown") + " (" + String(item.score || 0) + "/100)",
      "Primary Trigger: " + (item.primaryTrigger || "None"),
      "Threat Lane: " + (item.threatLane || "No dominant lane"),
      "Target: " + (item.target || "Unknown"),
      "Root Domain: " + (item.root || "n/a"),
      "Next Move: " + (item.next || "Use official routes before acting."),
      "Case Reference: " + (item.caseReference || item.casePacketId || "not generated"),
      "Evidence Digest: " + (item.evidenceDigest || "n/a"),
      item.notes ? "Notes: " + item.notes : "Notes: none",
      item.onlineFindingsNotes ? "Online Intel Findings: " + item.onlineFindingsNotes : "Online Intel Findings: none",
      "",
      "Evidence:",
      ...((item.evidence && item.evidence.length ? item.evidence : ["No compact evidence stored."]).map(entry => "- " + entry)),
      "",
      "Privacy: This item was copied from browser-local history. No cloud account, telemetry, or hidden online lookup is involved."
    ].join("\n");
  }

  function renderHistory(){
    if (!els.historyList) return;
    const items = readHistory();
    els.historyList.innerHTML = "";
    if (els.historyStatus) els.historyStatus.textContent = items.length ? (items.length + " recent scan" + (items.length === 1 ? "" : "s") + " stored on this device only.") : "No local scan history yet.";
    if (!items.length) { const li = document.createElement("li"); li.textContent = "No local scan history yet. Run a scan to save a private on-device entry."; els.historyList.appendChild(li); return; }
    items.forEach((item, index) => {
      const li = document.createElement("li");
      li.className = "history-card";
      const title = document.createElement("b");
      title.textContent = (item.risk || "Unknown") + " · " + String(item.score || 0) + "/100";
      const target = document.createElement("span");
      target.textContent = item.root || item.target || "Unknown target";
      const meta = document.createElement("small");
      meta.textContent = (item.time || "Unknown time") + " · " + (item.inputType || "Unknown input") + " · " + (item.primaryTrigger || "No trigger");
      li.appendChild(title); li.appendChild(document.createElement("br"));
      li.appendChild(target); li.appendChild(document.createElement("br"));
      li.appendChild(meta);
      if (item.notes) { const p = document.createElement("p"); p.textContent = item.notes; li.appendChild(p); }
      const actions = document.createElement("div");
      actions.className = "history-item-actions";
      [
        ["load", "View Previous Scan"],
        ["copy", "Copy Previous Result"],
        ["delete", "Delete"]
      ].forEach(([action, label]) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = action === "delete" ? "ghost-button compact-copy danger-action" : "ghost-button compact-copy";
        button.dataset.historyAction = action;
        button.dataset.historyIndex = String(index);
        button.textContent = label;
        actions.appendChild(button);
      });
      li.appendChild(actions);
      els.historyList.appendChild(li);
    });
  }

  function handleHistoryAction(event){
    const button = event.target && event.target.closest ? event.target.closest("[data-history-action]") : null;
    if (!button) return;
    const items = readHistory();
    const index = Number(button.dataset.historyIndex || "-1");
    const item = items[index];
    if (!item) return;
    const action = button.dataset.historyAction;
    if (action === "load") {
      els.input.value = item.target || "";
      if (els.copyStatus) els.copyStatus.textContent = "Previous scan loaded and rechecked locally.";
      runScan();
      return;
    }
    if (action === "copy") {
      copyText(buildHistoryText(item), "Previous scan result");
      return;
    }
    if (action === "delete") {
      items.splice(index, 1);
      writeHistory(items);
      renderHistory();
      if (els.copyStatus) els.copyStatus.textContent = "One local history item deleted.";
    }
  }

  function saveCase(){
    if (!lastReport || !lastReport.raw) runScan();
    if (!lastReport || !lastReport.raw) return;
    addScanToHistory(lastReport, "manual");
    if (els.copyStatus) els.copyStatus.textContent = "Current scan saved to local scan history on this device.";
  }

  document.querySelectorAll("[data-example]").forEach(button => {
    button.addEventListener("click", () => {
      els.input.value = button.getAttribute("data-example") || "";
      els.input.dispatchEvent(new Event("input", { bubbles: true }));
      window.ProxumaPendingScanSource = "example-button";
      els.scanButton.click();
    });
  });
  els.scanButton.addEventListener("click", () => runScan(window.ProxumaPendingScanSource || "analyze-button"));
  if (els.input) els.input.addEventListener("input", updateDetectedInputType);
  updateDetectedInputType();
  els.input.addEventListener("keydown", event => {
    if (event.key === "Enter") {
      event.preventDefault();
      window.ProxumaPendingScanSource = "keyboard-enter";
      els.scanButton.click();
    }
  });
  els.saveCaseButton.addEventListener("click", saveCase);
  els.clearHistoryButton.addEventListener("click", () => { localStorage.removeItem(HISTORY_KEY); renderHistory(); if (els.copyStatus) els.copyStatus.textContent = "Local scan history cleared. Pattern memory was left alone."; });
  if (els.clearAllLocalDataButton) els.clearAllLocalDataButton.addEventListener("click", () => {
    try {
      localStorage.removeItem(HISTORY_KEY);
      localStorage.removeItem(LAST_SCAN_KEY);
      localStorage.removeItem(PATTERN_MEMORY_KEY);
      localStorage.removeItem(ONLINE_CONSENT_KEY);
      localStorage.removeItem(ONLINE_FINDINGS_KEY);
    } catch(error) {}
    renderHistory();
    renderPatternMemoryDashboard();
    renderOnlineConsentPanel(lastReport || emptyReport());
    if (els.copyStatus) els.copyStatus.textContent = "All Proxuma IT local scan/history/memory choices were cleared on this device.";
  });
  if (els.historyList) els.historyList.addEventListener("click", handleHistoryAction);
  if (els.copyMemorySummaryButton) els.copyMemorySummaryButton.addEventListener("click", copyMemorySummary);
  if (els.downloadMemoryJsonButton) els.downloadMemoryJsonButton.addEventListener("click", downloadMemoryJson);
  if (els.clearPatternMemoryButton) els.clearPatternMemoryButton.addEventListener("click", clearPatternMemory);
  if (els.enableOnlineConsentButton) els.enableOnlineConsentButton.addEventListener("click", enableOnlineConsent);
  if (els.revokeOnlineConsentButton) els.revokeOnlineConsentButton.addEventListener("click", revokeOnlineConsent);
  if (els.onlineRunPreviewButton) els.onlineRunPreviewButton.addEventListener("click", previewOnlineIntelRun);
  if (els.onlineLookupLinksButton) els.onlineLookupLinksButton.addEventListener("click", generateOnlineLookupLinks);
  if (els.onlineRdapLookupButton) els.onlineRdapLookupButton.addEventListener("click", runConsentGatedRdapLookup);
  if (els.saveOnlineFindingsButton) els.saveOnlineFindingsButton.addEventListener("click", saveOnlineFindingsNotes);
  if (els.clearOnlineFindingsButton) els.clearOnlineFindingsButton.addEventListener("click", clearOnlineFindingsNotes);




  if (els.copyReportButton) els.copyReportButton.addEventListener("click", copyFullReport);
  if (els.copySummaryButton) els.copySummaryButton.addEventListener("click", copyCleanSummary);
  if (els.copyCasePacketButton) els.copyCasePacketButton.addEventListener("click", copyCasePacket);
  if (els.downloadCaseTextButton) els.downloadCaseTextButton.addEventListener("click", downloadCaseText);
  if (els.downloadCasePacketButton) els.downloadCasePacketButton.addEventListener("click", downloadCasePacket);
  if (els.explainVerdictButton) els.explainVerdictButton.addEventListener("click", explainVerdict);
  if (els.userViewButton) els.userViewButton.addEventListener("click", () => setAudienceView("user"));
  if (els.analystViewButton) els.analystViewButton.addEventListener("click", () => setAudienceView("analyst"));
  if (els.qrStartButton) els.qrStartButton.addEventListener("click", startQrScanner);
  if (els.qrStopButton) els.qrStopButton.addEventListener("click", stopQrScanner);
  window.addEventListener("pagehide", stopQrScanner);

  document.querySelectorAll(".compact-detail").forEach(detail => {
    detail.addEventListener("toggle", () => {
      if (!detail.open) return;
      document.querySelectorAll(".compact-detail[open]").forEach(other => { if (other !== detail) other.open = false; });
    });
  });


  function setupGuidanceDrawer(){
    const tabs = Array.from(document.querySelectorAll(".guidance-tab"));
    const panels = Array.from(document.querySelectorAll(".guidance-panel"));
    if (!tabs.length || !panels.length) return;
    function activate(targetId){
      tabs.forEach(tab => {
        const isActive = tab.getAttribute("data-guidance-target") === targetId;
        tab.classList.toggle("active", isActive);
        tab.setAttribute("aria-selected", isActive ? "true" : "false");
      });
      let activePanel = null;
      panels.forEach(panel => {
        const isActive = panel.id === targetId;
        panel.classList.toggle("active", isActive);
        panel.hidden = !isActive;
        if (isActive) activePanel = panel;
      });
      if (activePanel && window.matchMedia("(max-width: 900px)").matches) {
        if (!activePanel.querySelector(".drawer-panel-mobile-marker")) {
          const marker = document.createElement("span");
          marker.className = "drawer-panel-mobile-marker";
          marker.textContent = "Selected information";
          activePanel.insertBefore(marker, activePanel.firstChild);
        }
        window.requestAnimationFrame(() => {
          activePanel.scrollIntoView({ behavior: "smooth", block: "start" });
          const heading = activePanel.querySelector("h3");
          if (heading) heading.setAttribute("tabindex", "-1");
        });
      }
    }
    tabs.forEach(tab => {
      tab.addEventListener("click", () => activate(tab.getAttribute("data-guidance-target")));
    });
    activate("guidanceNextPanel");
  }

  function setupIntelligenceDrawer(){
    const drawer = document.getElementById("details");
    const tabList = drawer ? drawer.querySelector(".drawer-tabs") : null;
    const stage = drawer ? drawer.querySelector(".drawer-stage") : null;
    const tabs = drawer ? Array.from(drawer.querySelectorAll(".drawer-tab")) : [];
    const panels = drawer ? Array.from(drawer.querySelectorAll(".drawer-panel")) : [];
    if (!drawer || !tabList || !stage || !tabs.length || !panels.length) return;

    let mobilePicker = drawer.querySelector(".mobile-investigation-picker");
    let mobileSelect = null;
    let mobileCurrent = null;

    if (!mobilePicker) {
      mobilePicker = document.createElement("div");
      mobilePicker.className = "mobile-investigation-picker";
      mobilePicker.innerHTML = `
        <label for="mobileInvestigationSelect">Choose information</label>
        <select id="mobileInvestigationSelect" aria-label="Choose investigation information"></select>
        <p class="mobile-investigation-current" aria-live="polite"></p>
      `;
      tabList.insertAdjacentElement("afterend", mobilePicker);
    }

    mobileSelect = mobilePicker.querySelector("select");
    mobileCurrent = mobilePicker.querySelector(".mobile-investigation-current");
    mobileSelect.innerHTML = "";
    tabs.forEach(tab => {
      if (tab.hidden) return;
      const option = document.createElement("option");
      option.value = tab.getAttribute("data-drawer-target") || "";
      option.textContent = tab.textContent.trim();
      mobileSelect.appendChild(option);
    });

    function activate(targetId, options = {}){
      let activePanel = null;
      let activeTab = null;
      tabs.forEach(tab => {
        const isActive = tab.getAttribute("data-drawer-target") === targetId;
        tab.classList.toggle("active", isActive);
        tab.setAttribute("aria-selected", isActive ? "true" : "false");
        if (isActive) activeTab = tab;
      });
      panels.forEach(panel => {
        const isActive = panel.id === targetId;
        panel.classList.toggle("active", isActive);
        panel.hidden = !isActive;
        if (isActive) activePanel = panel;
      });
      if (!activePanel || !activeTab) return;

      if (mobileSelect && Array.from(mobileSelect.options).some(option => option.value === targetId)) {
        mobileSelect.value = targetId;
      }
      if (mobileCurrent) {
        mobileCurrent.textContent = activeTab.textContent.trim();
      }

      if (window.matchMedia("(max-width: 900px)").matches) {
        let marker = activePanel.querySelector(":scope > .drawer-panel-mobile-marker");
        if (!marker) {
          marker = document.createElement("span");
          marker.className = "drawer-panel-mobile-marker";
          activePanel.insertBefore(marker, activePanel.firstChild);
        }
        marker.textContent = activeTab.textContent.trim();

        if (options.reveal !== false) {
          window.requestAnimationFrame(() => {
            activePanel.scrollIntoView({ behavior: "smooth", block: "start" });
            const heading = activePanel.querySelector("h3");
            if (heading) {
              heading.setAttribute("tabindex", "-1");
              window.setTimeout(() => heading.focus({ preventScroll: true }), 350);
            }
          });
        }
      }
    }

    tabs.forEach(tab => {
      tab.addEventListener("click", () => activate(tab.getAttribute("data-drawer-target"), { reveal: true }));
    });
    mobileSelect.addEventListener("change", () => activate(mobileSelect.value, { reveal: true }));
    activate("explainPanel", { reveal: false });
  }


  function setupInvestigationSummary(){
    const sourceIds = {
      scoreValue: "investigationSummaryScore",
      confidenceLabel: "investigationSummaryConfidence",
      whyScore: "investigationSummaryConcern",
      actionText: "investigationSummaryAction"
    };
    const details = document.getElementById("details");
    const sync = () => {
      Object.entries(sourceIds).forEach(([sourceId, targetId]) => {
        const source = document.getElementById(sourceId);
        const target = document.getElementById(targetId);
        if (source && target) target.textContent = (source.textContent || "").trim() || "—";
      });
      const score = (document.getElementById("scoreValue")?.textContent || "").trim();
      if (details) details.classList.toggle("is-analysis-loading", /analyz|scanning|checking/i.test(score));
    };
    Object.keys(sourceIds).forEach(id => {
      const source = document.getElementById(id);
      if (source) new MutationObserver(sync).observe(source,{subtree:true,childList:true,characterData:true});
    });
    sync();
  }

  function setupCollapsibleCards(){
    const cards = Array.from(document.querySelectorAll(".collapsible-card[data-collapse-key]"));
    cards.forEach(card => {
      const button = card.querySelector(".collapse-toggle");
      if (!button) return;
      const bodyId = button.getAttribute("aria-controls");
      const body = bodyId ? document.getElementById(bodyId) : card.querySelector(".collapsible-card-body");
      if (!body) return;
      const key = card.getAttribute("data-collapse-key");
      const expandedLabel = button.getAttribute("data-expanded-label") || "Hide";
      const collapsedLabel = button.getAttribute("data-collapsed-label") || "Show";
      const copy = button.querySelector(".toggle-copy") || button;
      const defaultCollapsed = card.getAttribute("data-default-collapsed") === "true";
      let collapsed = defaultCollapsed;
      try {
        const savedCollapseState = localStorage.getItem(key);
        collapsed = savedCollapseState === null ? defaultCollapsed : savedCollapseState === "true";
      } catch(error) { collapsed = defaultCollapsed; }
      function applyState(isCollapsed){
        card.classList.toggle("is-collapsed", isCollapsed);
        button.setAttribute("aria-expanded", isCollapsed ? "false" : "true");
        copy.textContent = isCollapsed ? collapsedLabel : expandedLabel;
        body.hidden = isCollapsed;
        try { localStorage.setItem(key, String(isCollapsed)); } catch(error) {}
      }
      button.addEventListener("click", () => applyState(!card.classList.contains("is-collapsed")));
      applyState(collapsed);
    });
  }

  setupCollapsibleCards();
  setupGuidanceDrawer();
  setupIntelligenceDrawer();
  setupInvestigationSummary();
  try { audienceView = localStorage.getItem("proxuma-it-audience-view-v1") || "user"; } catch(error) { audienceView = "user"; }
  setAudienceView(audienceView, false);
  renderReport(emptyReport());
  renderHistory();


})();
