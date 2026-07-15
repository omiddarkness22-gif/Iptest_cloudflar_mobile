import React, { useState, useEffect } from "react";
import { Language, IPScanResult, VpnConfig } from "../types";
import { Copy, Check, Settings, Code, FileText, ArrowRight, HelpCircle, RefreshCw, Globe, User, Lock, CloudLightning, AlertCircle, Key } from "lucide-react";

interface ConfigGeneratorTabProps {
  language: Language;
  cleanIps: IPScanResult[];
  favorites: string[];
  onToggleFavorite: (ip: string) => void;
}

export const ConfigGeneratorTab: React.FC<ConfigGeneratorTabProps> = ({
  language,
  cleanIps,
  favorites,
  onToggleFavorite
}) => {
  const [rawConfig, setRawConfig] = useState<string>("");
  const [parsedConfig, setParsedConfig] = useState<VpnConfig | null>(null);
  const [parseError, setParseError] = useState<string>("");
  const [generatedConfigs, setGeneratedConfigs] = useState<Array<{ ip: string; url: string; delay?: number }>>([]);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [copiedAll, setCopiedAll] = useState<boolean>(false);

  // 3x-ui Sync States
  const [panelUrl, setPanelUrl] = useState(() => localStorage.getItem("cf_3xui_url") || "");
  const [authMethod, setAuthMethod] = useState<"credentials" | "cookie" | "token">(
    () => (localStorage.getItem("cf_3xui_auth_method") as "credentials" | "cookie" | "token") || "credentials"
  );
  const [username, setUsername] = useState(() => localStorage.getItem("cf_3xui_username") || "");
  const [password, setPassword] = useState(() => localStorage.getItem("cf_3xui_password") || "");
  const [sessionCookie, setSessionCookie] = useState(() => localStorage.getItem("cf_3xui_session_cookie") || "");
  const [apiToken, setApiToken] = useState(() => localStorage.getItem("cf_3xui_api_token") || "");
  const [inboundTag, setInboundTag] = useState(() => localStorage.getItem("cf_3xui_inbound") || "");
  const [security, setSecurity] = useState(() => localStorage.getItem("cf_3xui_security") || "same");
  const [remarkPrefix, setRemarkPrefix] = useState(() => localStorage.getItem("cf_3xui_prefix") || "");
  const [isSyncing, setIsSyncing] = useState(false);
  const [syncStatus, setSyncStatus] = useState<{ 
    success?: boolean; 
    message?: string; 
    results?: Array<{ ip: string; success: boolean; error?: string; diagnostics?: any[] }> 
  } | null>(null);
  const [syncSource, setSyncSource] = useState<"clean" | "favorites">("clean");
  const [syncPort, setSyncPort] = useState<number>(443);

  // Dynamic Inbound States
  const [inbounds, setInbounds] = useState<any[]>([]);
  const [isFetchingInbounds, setIsFetchingInbounds] = useState(false);
  const [fetchInboundsError, setFetchInboundsError] = useState("");

  const isEn = language === "en";

  useEffect(() => {
    if (parsedConfig) {
      if (!inboundTag) {
        setInboundTag(parsedConfig.protocol);
      }
      if (!security) {
        setSecurity(parsedConfig.params["tls"] || "tls");
      }
      if (!remarkPrefix) {
        const cleanName = parsedConfig.remarks.split(" - ")[0] || "CleanCF";
        setRemarkPrefix(cleanName);
      }
      setSyncPort(parsedConfig.port || 443);
    }
  }, [parsedConfig]);

  const scannedCleanIps = cleanIps.filter(r => r.success).map(r => r.ip);
  const ipsToSync = syncSource === "clean" ? scannedCleanIps : favorites;

  const handleFetchInbounds = async () => {
    if (!panelUrl) {
      setFetchInboundsError(isEn ? "Please fill in Panel URL first." : "لطفاً ابتدا آدرس پنل را وارد کنید.");
      return;
    }
    setIsFetchingInbounds(true);
    setFetchInboundsError("");
    try {
      const response = await fetch("/api/3x-ui/inbounds", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          panelUrl,
          username: authMethod === "credentials" ? username : undefined,
          password: authMethod === "credentials" ? password : undefined,
          sessionCookie: authMethod === "cookie" ? sessionCookie : undefined,
          apiToken: authMethod === "token" ? apiToken : undefined
        })
      });

      const data = await response.json();
      if (response.ok && data.success) {
        setInbounds(data.inbounds || []);
        if (data.inbounds && data.inbounds.length > 0) {
          const tags = data.inbounds.map((inb: any) => inb.tag);
          if (!inboundTag || !tags.includes(inboundTag)) {
            setInboundTag(data.inbounds[0].tag);
          }
        }
      } else {
        setFetchInboundsError(data.error || (isEn ? "Failed to load inbounds." : "خطا در دریافت لیست اینباندها. اطلاعات اتصال را بررسی کنید."));
      }
    } catch (err: any) {
      setFetchInboundsError(err.message || (isEn ? "Connection error." : "خطای ارتباط با سرور."));
    } finally {
      setIsFetchingInbounds(false);
    }
  };

  const handleSyncToPanel = async () => {
    if (!panelUrl) {
      setSyncStatus({
        success: false,
        message: isEn ? "Please fill in Panel URL." : "لطفاً آدرس پنل را وارد کنید."
      });
      return;
    }

    if (authMethod === "cookie" && !sessionCookie) {
      setSyncStatus({
        success: false,
        message: isEn ? "Please enter Session Cookie." : "لطفاً کوکی نشست را وارد کنید."
      });
      return;
    }

    if (authMethod === "token" && !apiToken) {
      setSyncStatus({
        success: false,
        message: isEn ? "Please enter API Token." : "لطفاً توکن API را وارد کنید."
      });
      return;
    }

    if (authMethod === "credentials" && (!username || !password)) {
      setSyncStatus({
        success: false,
        message: isEn ? "Please enter Username and Password." : "لطفاً نام کاربری و رمز عبور را وارد کنید."
      });
      return;
    }

    if (ipsToSync.length === 0) {
      setSyncStatus({
        success: false,
        message: isEn
          ? "No IP addresses found to sync. Please scan or select some first."
          : "هیچ آی‌پی آدرسی برای ثبت وجود ندارد. لطفا ابتدا اسکن کنید یا چند آی‌پی به علاقه‌مندی‌ها اضافه کنید."
      });
      return;
    }

    setIsSyncing(true);
    setSyncStatus(null);

    // Save connection info to localStorage
    localStorage.setItem("cf_3xui_url", panelUrl);
    localStorage.setItem("cf_3xui_auth_method", authMethod);
    localStorage.setItem("cf_3xui_username", username);
    localStorage.setItem("cf_3xui_password", password);
    localStorage.setItem("cf_3xui_session_cookie", sessionCookie);
    localStorage.setItem("cf_3xui_api_token", apiToken);
    localStorage.setItem("cf_3xui_inbound", inboundTag);
    localStorage.setItem("cf_3xui_security", security);
    localStorage.setItem("cf_3xui_prefix", remarkPrefix);

    try {
      // Prepare hosts list from selected source
      const selectedInbound = inbounds.find(inb => inb.tag === inboundTag);
      const hostsToSync = ipsToSync.map((ip) => ({
        remark: `${remarkPrefix || "CleanCF"}-${ip}`,
        endpoint: ip,
        port: Number(syncPort) || 443,
        inbound: inboundTag || "",
        inboundId: selectedInbound ? selectedInbound.id : undefined,
        security: security || "tls",
        enable: true
      }));

      const response = await fetch("/api/3x-ui/sync-hosts", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          panelUrl,
          username: authMethod === "credentials" ? username : undefined,
          password: authMethod === "credentials" ? password : undefined,
          sessionCookie: authMethod === "cookie" ? sessionCookie : undefined,
          apiToken: authMethod === "token" ? apiToken : undefined,
          hosts: hostsToSync
        })
      });

      let data: any = {};
      try {
        const text = await response.text();
        data = JSON.parse(text);
      } catch (e) {
        throw new Error(
          isEn 
            ? `Invalid server response (Status ${response.status}). The panel might be unreachable, offline, or timed out.`
            : `پاسخ نامعتبر از سرور (وضعیت ${response.status}). سرور پنل شما احتمالاً خاموش است، پورت آن بسته است یا درخواست با اتمام زمان مواجه شده است.`
        );
      }

      if (response.ok && data.success) {
        setSyncStatus({
          success: true,
          message: isEn
            ? `Successfully registered ${data.successCount} clean IPs as hosts in your 3x-ui panel!`
            : `تعداد ${data.successCount} آی‌پی تمیز با موفقیت در بخش Hosts پنل سنایی شما ثبت شد!`,
          results: data.results
        });
      } else {
        setSyncStatus({
          success: false,
          message: data.error || (isEn ? "Failed to sync hosts to the panel." : "خطا در ثبت آی‌پی‌ها در پنل سنایی."),
          results: data.results
        });
      }
    } catch (err: any) {
      setSyncStatus({
        success: false,
        message: err.message || (isEn ? "Connection error." : "خطا در برقراری ارتباط با سرور.")
      });
    } finally {
      setIsSyncing(false);
    }
  };

  const t = {
    title: isEn ? "Cloudflare VPN Config Customizer" : "شخصی‌سازی کانفیگ VPN با آی‌پی کلادفلر",
    subtitle: isEn 
      ? "Paste your VLESS, Trojan, or VMess config, select your clean IPs, and instantly generate optimized proxy configurations." 
      : "کانفیگ خام خود (VLESS، VMess، Trojan) را وارد کرده و با ترکیب آی‌پی‌های تمیز اسکن‌شده، کانفیگ‌های نهایی بسازید.",
    inputPlaceholder: isEn 
      ? "Paste your VPN Link here (vless://, trojan://, vmess://)..." 
      : "لینک کانفیگ خود را اینجا وارد کنید (مثلا vless://)...",
    parseSuccess: isEn ? "Config parsed successfully!" : "کانفیگ با موفقیت شناسایی شد!",
    invalidConfig: isEn ? "Invalid config URL format." : "فرمت لینک وارد شده نامعتبر است.",
    parseBtn: isEn ? "Analyze Config" : "آنالیز و بررسی کانفیگ",
    detailsHeader: isEn ? "Config Specifications" : "مشخصات فنی کانفیگ",
    protocolLabel: isEn ? "Protocol" : "پروتکل",
    hostLabel: isEn ? "Original Host / SNI" : "آدرس اصلی / SNI",
    portLabel: isEn ? "Port" : "پورت",
    pathLabel: isEn ? "Path" : "مسیر (Path)",
    remarksLabel: isEn ? "Remarks (Name)" : "نام کانفیگ",
    noCleanIps: isEn 
      ? "No clean IPs found. Run a scan first or add presets in IP Manager!" 
      : "هیچ آی‌پی تمیزی یافت نشد. ابتدا اسکن کنید یا از بخش مدیریت آی‌پی به لیست تست بیفزایید!",
    generateHeader: isEn ? "Generated Configs with Clean IPs" : "کانفیگ‌های تولید شده با آی‌پی‌های تمیز",
    generateSub: isEn 
      ? "Select from successful clean IPs to output functional client settings." 
      : "کانفیگ‌های نهایی بهینه‌شده آماده برای کپی و استفاده در نرم‌افزارها (v2rayNG, Nekobox, Shadowrocket)",
    copyAllBtn: isEn ? "Copy All Configurations" : "کپی همه‌ی کانفیگ‌ها به صورت یکجا",
    copyBtn: isEn ? "Copy Link" : "کپی لینک",
    copied: isEn ? "Copied!" : "کپی شد!",
    howItWorksTitle: isEn ? "How does this work?" : "چگونه کار می‌کند؟",
    howItWorksDesc: isEn
      ? "A VPN config communicates with a target domain through a Cloudflare CDN IP. By replacing the destination domain with a pre-scanned 'Clean Cloudflare IP' while maintaining the host headers and SNI, you bypass censorship, improve speeds, and reduce connection drops."
      : "یک کانفیگ کلادفلر از طریق یک آی‌پی لبه به دامنه اصلی شما متصل می‌شود. با جایگزینی دامنه مقصد با یک «آی‌پی تمیز کلادفلر» و همزمان نگه داشتن SNI و Host روی دامنه اصلی، فیلترینگ دور زده شده و سرعت اتصال فوق‌العاده افزایش می‌یابد."
  };

  const handleParse = (inputVal?: string) => {
    const value = (inputVal || rawConfig).trim();
    if (!value) return;

    setParseError("");
    setParsedConfig(null);

    try {
      if (value.startsWith("vless://") || value.startsWith("trojan://")) {
        // vless://uuid@domain:port?params#remarks
        const protocol = value.startsWith("vless://") ? "vless" : "trojan";
        const urlPart = value.substring(protocol.length + 3);
        
        // Find split indices
        const atIdx = urlPart.indexOf("@");
        const hashIdx = urlPart.indexOf("#");
        
        if (atIdx === -1) {
          setParseError(t.invalidConfig);
          return;
        }

        const uuidOrPassword = urlPart.substring(0, atIdx);
        
        let remaining = hashIdx !== -1 ? urlPart.substring(atIdx + 1, hashIdx) : urlPart.substring(atIdx + 1);
        const remarks = hashIdx !== -1 ? decodeURIComponent(urlPart.substring(hashIdx + 1)) : "Clean Cloudflare";

        const questionIdx = remaining.indexOf("?");
        let addressPortStr = questionIdx !== -1 ? remaining.substring(0, questionIdx) : remaining;
        let queryStr = questionIdx !== -1 ? remaining.substring(questionIdx + 1) : "";

        const colonIdx = addressPortStr.lastIndexOf(":");
        if (colonIdx === -1) {
          setParseError(t.invalidConfig);
          return;
        }

        const address = addressPortStr.substring(0, colonIdx);
        const port = parseInt(addressPortStr.substring(colonIdx + 1), 10);

        const params: Record<string, string> = {};
        if (queryStr) {
          const pairs = queryStr.split("&");
          pairs.forEach(p => {
            const [k, v] = p.split("=");
            if (k) params[k] = v || "";
          });
        }

        setParsedConfig({
          raw: value,
          protocol,
          uuid: uuidOrPassword,
          address,
          port,
          params,
          remarks
        });
      } else if (value.startsWith("vmess://")) {
        // vmess://base64encoded
        const base64Str = value.substring(8).trim();
        const decodedStr = atob(base64Str);
        const json = JSON.parse(decodedStr);

        const params: Record<string, string> = {};
        if (json.host) params["host"] = json.host;
        if (json.path) params["path"] = json.path;
        if (json.tls) params["tls"] = json.tls;
        if (json.sni) params["sni"] = json.sni;
        if (json.net) params["net"] = json.net;

        setParsedConfig({
          raw: value,
          protocol: "vmess",
          uuid: json.id,
          address: json.add,
          port: Number(json.port) || 443,
          params,
          remarks: json.ps || "Clean Cloudflare"
        });
      } else {
        setParseError(t.invalidConfig);
      }
    } catch (err: any) {
      setParseError(isEn ? `Failed to parse: ${err.message}` : "خطا در تجزیه لینک کانفیگ. مطمئن شوید فرمت لینک درست است.");
    }
  };

  useEffect(() => {
    if (!parsedConfig) {
      setGeneratedConfigs([]);
      return;
    }

    // Generate modified configs using scanned clean IPs or presets
    const ipsToUse = cleanIps.filter(r => r.success).map(r => ({ ip: r.ip, latency: r.latency })) || [];
    
    // If no scanned clean IPs, use favorites
    if (ipsToUse.length === 0 && favorites.length > 0) {
      favorites.forEach(f => {
        ipsToUse.push({ ip: f, latency: undefined });
      });
    }

    const configs = ipsToUse.map(({ ip, latency }) => {
      let modifiedUrl = "";
      const remarksSuffix = latency ? ` (Ping: ${latency}ms)` : "";
      const cleanRemarks = `${parsedConfig.remarks} - CF: ${ip}${remarksSuffix}`;

      if (parsedConfig.protocol === "vless" || parsedConfig.protocol === "trojan") {
        // Prepare query parameters
        const updatedParams = { ...parsedConfig.params };
        
        // Ensure SNI and Host are preserved with original domain
        if (!updatedParams["sni"]) {
          updatedParams["sni"] = parsedConfig.address;
        }
        if (!updatedParams["host"]) {
          updatedParams["host"] = parsedConfig.address;
        }

        const queryParts = Object.entries(updatedParams).map(([k, v]) => `${k}=${v}`);
        const queryStr = queryParts.length > 0 ? `?${queryParts.join("&")}` : "";

        modifiedUrl = `${parsedConfig.protocol}://${parsedConfig.uuid}@${ip}:${parsedConfig.port}${queryStr}#${encodeURIComponent(cleanRemarks)}`;
      } else if (parsedConfig.protocol === "vmess") {
        const vmessJson = {
          v: "2",
          ps: cleanRemarks,
          add: ip,
          port: String(parsedConfig.port),
          id: parsedConfig.uuid,
          aid: "0",
          scy: "auto",
          net: parsedConfig.params["net"] || "ws",
          type: "none",
          host: parsedConfig.params["host"] || parsedConfig.address,
          path: parsedConfig.params["path"] || "",
          tls: parsedConfig.params["tls"] || "tls",
          sni: parsedConfig.params["sni"] || parsedConfig.address
        };
        modifiedUrl = `vmess://${btoa(JSON.stringify(vmessJson))}`;
      }

      return {
        ip,
        url: modifiedUrl,
        delay: latency
      };
    });

    setGeneratedConfigs(configs);
  }, [parsedConfig, cleanIps, favorites]);

  const handleCopyOne = (url: string, index: number) => {
    navigator.clipboard.writeText(url);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const handleCopyAll = () => {
    if (generatedConfigs.length === 0) return;
    const allUrls = generatedConfigs.map(c => c.url).join("\n");
    navigator.clipboard.writeText(allUrls);
    setCopiedAll(true);
    setTimeout(() => setCopiedAll(false), 2000);
  };

  return (
    <div className="space-y-6" id="config-generator-root">
      {/* Title block */}
      <div className="bg-gray-900 border border-gray-800 rounded-3xl p-6 shadow-xl" id="config-top-intro">
        <div className="flex items-start space-x-4 ml-2">
          <div className="p-3 bg-indigo-500/10 text-indigo-400 rounded-2xl">
            <Settings className="w-6 h-6 animate-spin-slow" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white font-sans">{t.title}</h3>
            <p className="text-xs text-gray-400 mt-1">{t.subtitle}</p>
          </div>
        </div>

        {/* Input box */}
        <div className="mt-6 space-y-4">
          <textarea
            value={rawConfig}
            onChange={(e) => {
              setRawConfig(e.target.value);
              if (e.target.value) handleParse(e.target.value);
            }}
            placeholder={t.inputPlaceholder}
            dir="ltr"
            className="w-full h-24 bg-gray-950 border border-gray-800 rounded-2xl px-4 py-3 text-sm font-mono text-gray-300 placeholder-gray-600 focus:outline-none focus:border-indigo-500 resize-none transition-all"
          />

          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            {parseError && (
              <span className="text-xs text-rose-400 font-semibold">{parseError}</span>
            )}
            {parsedConfig && (
              <span className="text-xs text-emerald-400 font-semibold flex items-center">
                <Check className="w-4 h-4 ml-1" />
                {t.parseSuccess} ({parsedConfig.protocol.toUpperCase()})
              </span>
            )}
            {!parseError && !parsedConfig && <span />}

            <button
              onClick={() => handleParse()}
              className="w-full sm:w-auto bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm px-6 py-3 rounded-2xl transition-all shadow-md"
            >
              {t.parseBtn}
            </button>
          </div>
        </div>
      </div>

      {/* Grid of details & how it works */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6" id="config-grid">
        {/* Analyzed Config Specs */}
        {parsedConfig && (
          <div className="bg-gray-900 border border-gray-800 rounded-3xl p-6 shadow-xl lg:col-span-1 h-fit" id="config-specs-card">
            <h4 className="text-sm font-bold text-white mb-4 flex items-center">
              <Code className="w-4 h-4 ml-2 text-indigo-400" />
              {t.detailsHeader}
            </h4>

            <div className="space-y-4 text-xs font-sans">
              <div className="flex justify-between py-2 border-b border-gray-850">
                <span className="text-gray-500">{t.protocolLabel}</span>
                <span className="font-bold text-indigo-400 uppercase">{parsedConfig.protocol}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-gray-850">
                <span className="text-gray-500">{t.portLabel}</span>
                <span className="font-mono font-bold text-gray-300">{parsedConfig.port}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-gray-850">
                <span className="text-gray-500">TLS</span>
                <span className={`font-bold ${parsedConfig.params["tls"] === "none" ? "text-rose-400" : "text-emerald-400"}`}>
                  {parsedConfig.params["tls"] || "tls"}
                </span>
              </div>
              <div className="flex flex-col py-2 border-b border-gray-850 space-y-1">
                <span className="text-gray-500">{t.hostLabel}</span>
                <span className="font-mono font-bold text-gray-300 break-all text-right select-all">{parsedConfig.address}</span>
              </div>
              {parsedConfig.params["path"] && (
                <div className="flex flex-col py-2 border-b border-gray-850 space-y-1">
                  <span className="text-gray-500">{t.pathLabel}</span>
                  <span className="font-mono text-gray-400 break-all text-right select-all">{decodeURIComponent(parsedConfig.params["path"])}</span>
                </div>
              )}
              <div className="flex flex-col py-2 space-y-1">
                <span className="text-gray-500">{t.remarksLabel}</span>
                <span className="font-semibold text-gray-300 text-right">{parsedConfig.remarks}</span>
              </div>
            </div>
          </div>
        )}

        {/* Explain Card */}
        <div className={`bg-gray-900/60 border border-gray-800 rounded-3xl p-6 shadow-xl ${parsedConfig ? "lg:col-span-2" : "lg:col-span-3"}`} id="how-it-works-card">
          <h4 className="text-sm font-bold text-white mb-3 flex items-center">
            <HelpCircle className="w-4 h-4 ml-2 text-indigo-400" />
            {t.howItWorksTitle}
          </h4>
          <p className="text-xs text-gray-400 leading-relaxed font-sans">{t.howItWorksDesc}</p>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-6">
            <div className="bg-gray-950 p-4 rounded-2xl border border-gray-850 flex flex-col justify-between">
              <span className="text-indigo-400 font-bold text-lg font-mono">01</span>
              <p className="text-xs text-gray-300 font-medium mt-2">
                {isEn ? "Paste original VPN configuration URL" : "قرار دادن لینک کانفیگ وی‌پی‌ان خام"}
              </p>
            </div>
            <div className="bg-gray-950 p-4 rounded-2xl border border-gray-850 flex flex-col justify-between">
              <span className="text-indigo-400 font-bold text-lg font-mono">02</span>
              <p className="text-xs text-gray-300 font-medium mt-2">
                {isEn ? "IP changes to Cloudflare Clean IPs" : "اسکن و انتخاب آی‌پی تمیز و پرسرعت کلادفلر"}
              </p>
            </div>
            <div className="bg-gray-950 p-4 rounded-2xl border border-gray-850 flex flex-col justify-between">
              <span className="text-indigo-400 font-bold text-lg font-mono">03</span>
              <p className="text-xs text-gray-300 font-medium mt-2">
                {isEn ? "Import clean config into v2rayNG/Nekobox" : "کپی و ورود مستقیم به v2rayNG/Nekobox"}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Generated Config list */}
      {parsedConfig && (
        <>
          <div className="bg-gray-900 border border-gray-800 rounded-3xl p-6 shadow-xl" id="generated-configs-container">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 border-b border-gray-850 pb-6 mb-6">
            <div>
              <h4 className="text-md font-bold text-white font-sans flex items-center">
                <FileText className="w-5 h-5 ml-2 text-indigo-400" />
                {t.generateHeader}
              </h4>
              <p className="text-xs text-gray-400 mt-1">{t.generateSub}</p>
            </div>

            {generatedConfigs.length > 0 && (
              <button
                onClick={handleCopyAll}
                className="w-full sm:w-auto bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm px-6 py-3 rounded-2xl transition-all shadow-md flex items-center justify-center space-x-2"
              >
                {copiedAll ? <Check className="w-4 h-4 ml-1" /> : <Copy className="w-4 h-4 ml-1" />}
                <span>{copiedAll ? t.copied : t.copyAllBtn}</span>
              </button>
            )}
          </div>

          {generatedConfigs.length === 0 ? (
            <div className="text-center py-10 bg-gray-950 rounded-2xl border border-dashed border-gray-800 text-gray-500 text-sm font-medium">
              {t.noCleanIps}
            </div>
          ) : (
            <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
              {generatedConfigs.map((cfg, index) => (
                <div
                  key={`${cfg.ip}-${index}`}
                  className="bg-gray-950 border border-gray-850 hover:border-gray-800 rounded-2xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 transition-all"
                >
                  <div className="flex items-center space-x-3 ml-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-indigo-500 shadow-md shadow-indigo-500/20" />
                    <div>
                      <div className="flex items-center space-x-3">
                        <span className="font-mono text-sm font-bold text-gray-200 select-all">{cfg.ip}</span>
                        {cfg.delay && (
                          <span className="bg-emerald-500/10 text-emerald-400 font-mono text-xs font-semibold px-2 py-0.5 rounded-lg">
                            {cfg.delay} ms
                          </span>
                        )}
                      </div>
                      <p className="text-[10px] font-mono text-gray-500 truncate max-w-lg mt-1 select-all" dir="ltr">
                        {cfg.url}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleCopyOne(cfg.url, index)}
                      className="flex-1 md:flex-none bg-gray-900 text-gray-300 hover:bg-gray-850 px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center justify-center space-x-1 border border-gray-800"
                    >
                      {copiedIndex === index ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-400 ml-1" />
                          <span className="text-emerald-400">{t.copied}</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5 ml-1" />
                          <span>{t.copyBtn}</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
        </>
      )}

      {/* 3x-ui Panel Sync Card */}
      <div className="bg-gray-900 border border-gray-800 rounded-3xl p-6 shadow-xl mt-6" id="xui-panel-sync-container">
        <div className="flex items-start space-x-4 space-x-reverse ml-2 pb-4 border-b border-gray-850">
          <div className="p-3 bg-indigo-500/10 text-indigo-400 rounded-2xl ml-3">
            <CloudLightning className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <h4 className="text-md font-bold text-white font-sans">
              {isEn ? "Direct 3x-ui Panel Sync" : "ثبت خودکار در پنل سنایی (3x-ui)"}
            </h4>
            <p className="text-xs text-gray-400 mt-1">
              {isEn 
                ? "Automatically add the generated clean IPs directly to your 3x-ui panel's Hosts section."
                : "آی‌پی‌های تمیز اسکن‌شده را با یک کلیک به صورت مستقیم در بخش Hosts پنل سنایی خود ثبت کنید تا به عنوان پروکسی استفاده شوند."}
            </p>
          </div>
        </div>

        {/* IP Source Selector */}
        <div className="mt-5 bg-gray-950/40 p-4 rounded-2xl border border-gray-850">
          <label className="block text-xs font-bold text-gray-400 mb-2.5">
            {isEn ? "Select IP Source for Syncing" : "انتخاب منبع آی‌پی‌ها جهت ثبت در پنل"}
          </label>
          <div className="grid grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => setSyncSource("clean")}
              className={`py-3 px-4 text-xs font-bold rounded-xl border transition-all flex items-center justify-center gap-2 ${
                syncSource === "clean"
                  ? "bg-indigo-600/10 border-indigo-500 text-indigo-300"
                  : "bg-gray-950 border-gray-800 text-gray-400 hover:border-gray-700"
              }`}
            >
              <div className={`w-2 h-2 rounded-full ${syncSource === "clean" ? "bg-indigo-400 animate-pulse" : "bg-gray-600"}`} />
              <span>{isEn ? "Clean Scanned IPs" : "آی‌پی‌های تمیز اسکن شده"}</span>
              <span className="bg-gray-900 border border-gray-800 px-2 py-0.5 rounded-md font-mono text-[10px] text-gray-300">
                {scannedCleanIps.length}
              </span>
            </button>

            <button
              type="button"
              onClick={() => setSyncSource("favorites")}
              className={`py-3 px-4 text-xs font-bold rounded-xl border transition-all flex items-center justify-center gap-2 ${
                syncSource === "favorites"
                  ? "bg-indigo-600/10 border-indigo-500 text-indigo-300"
                  : "bg-gray-950 border-gray-800 text-gray-400 hover:border-gray-700"
              }`}
            >
              <div className={`w-2 h-2 rounded-full ${syncSource === "favorites" ? "bg-indigo-400 animate-pulse" : "bg-gray-600"}`} />
              <span>{isEn ? "Favorite/Saved IPs" : "آی‌پی‌های نشان‌شده (علاقه‌مندی)"}</span>
              <span className="bg-gray-900 border border-gray-800 px-2 py-0.5 rounded-md font-mono text-[10px] text-gray-300">
                {favorites.length}
              </span>
            </button>
          </div>
          
          {ipsToSync.length === 0 && (
            <p className="text-[10px] text-amber-500 font-semibold mt-3.5 leading-normal">
              ⚠️ {isEn 
                ? "Selected source is empty! Please scan some IPs or add favorites first." 
                : "منبع انتخابی خالی است! لطفا ابتدا اسکن انجام دهید یا تعدادی آی‌پی به علاقه‌مندی‌ها اضافه کنید."}
            </p>
          )}
        </div>

        <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Left Column: Login Credentials */}
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-bold text-gray-400 mb-2 flex items-center">
                <Globe className="w-3.5 h-3.5 ml-1.5 text-indigo-400" />
                {isEn ? "3x-ui Panel URL" : "آدرس پنل سنایی (Panel URL)"}
              </label>
              <input
                type="url"
                value={panelUrl}
                onChange={(e) => setPanelUrl(e.target.value)}
                dir="ltr"
                placeholder="http://domain-or-ip:8443/custom-path"
                className="w-full bg-gray-950 border border-gray-800 rounded-xl px-4 py-2.5 text-xs font-mono text-gray-300 placeholder-gray-600 focus:outline-none focus:border-indigo-500 transition-all"
              />
              <p className="text-[10px] text-gray-500 mt-1 leading-normal">
                {isEn 
                  ? "Include protocol (http/https), port, and custom path if configured." 
                  : "آدرس کامل پنل شامل http یا https، پورت پنل و مسیر اختصاصی (در صورت تنظیم) را وارد کنید."}
              </p>
            </div>

            {/* Auth Method Selector */}
            <div className="bg-gray-950/40 p-1.5 rounded-xl border border-gray-850 grid grid-cols-3 gap-1">
              <button
                type="button"
                onClick={() => setAuthMethod("credentials")}
                className={`py-1.5 text-[9px] sm:text-[10px] font-bold rounded-lg transition-all ${
                  authMethod === "credentials"
                    ? "bg-indigo-600 text-white shadow-sm"
                    : "text-gray-400 hover:text-gray-300"
                }`}
              >
                {isEn ? "Credentials" : "یوزرنیم و پسورد"}
              </button>
              <button
                type="button"
                onClick={() => setAuthMethod("cookie")}
                className={`py-1.5 text-[9px] sm:text-[10px] font-bold rounded-lg transition-all ${
                  authMethod === "cookie"
                    ? "bg-indigo-600 text-white shadow-sm"
                    : "text-gray-400 hover:text-gray-300"
                }`}
              >
                {isEn ? "Session" : "کوکی نشست"}
              </button>
              <button
                type="button"
                onClick={() => setAuthMethod("token")}
                className={`py-1.5 text-[9px] sm:text-[10px] font-bold rounded-lg transition-all ${
                  authMethod === "token"
                    ? "bg-indigo-600 text-white shadow-sm"
                    : "text-gray-400 hover:text-gray-300"
                }`}
              >
                {isEn ? "API Token" : "توکن API (جدید)"}
              </button>
            </div>

            {authMethod === "credentials" && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-bold text-gray-400 mb-2 flex items-center">
                    <User className="w-3.5 h-3.5 ml-1.5 text-indigo-400" />
                    {isEn ? "Username" : "نام کاربری پنل"}
                  </label>
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="admin"
                    className="w-full bg-gray-950 border border-gray-800 rounded-xl px-4 py-2.5 text-xs text-gray-300 placeholder-gray-600 focus:outline-none focus:border-indigo-500 transition-all"
                  />
                </div>
                <div>
                  <label className="block text-xs font-bold text-gray-400 mb-2 flex items-center">
                    <Lock className="w-3.5 h-3.5 ml-1.5 text-indigo-400" />
                    {isEn ? "Password" : "رمز عبور پنل"}
                  </label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full bg-gray-950 border border-gray-800 rounded-xl px-4 py-2.5 text-xs text-gray-300 placeholder-gray-600 focus:outline-none focus:border-indigo-500 transition-all"
                  />
                </div>
              </div>
            )}

            {authMethod === "cookie" && (
              <div>
                <label className="block text-xs font-bold text-gray-400 mb-2 flex items-center">
                  <Lock className="w-3.5 h-3.5 ml-1.5 text-indigo-400" />
                  {isEn ? "Session Cookie" : "کوکی نشست (Session Cookie)"}
                </label>
                <input
                  type="text"
                  value={sessionCookie}
                  onChange={(e) => setSessionCookie(e.target.value)}
                  dir="ltr"
                  placeholder="session=your_session_cookie_value_from_browser_devtools"
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl px-4 py-2.5 text-xs font-mono text-gray-300 placeholder-gray-600 focus:outline-none focus:border-indigo-500 transition-all"
                />
                <p className="text-[10px] text-gray-500 mt-1 leading-normal">
                  {isEn 
                    ? "Enter your raw cookie header or just the session=... value from browser DevTools (Application > Cookies). Bypasses login entirely." 
                    : "مقدار هدر Cookie یا بخش session=... را از تب Application > Cookies مرورگر خود کپی کرده و اینجا قرار دهید. این کار فرآیند ورود را کاملاً دور می‌زند."}
                </p>
              </div>
            )}

            {authMethod === "token" && (
              <div>
                <label className="block text-xs font-bold text-gray-400 mb-2 flex items-center">
                  <Key className="w-3.5 h-3.5 ml-1.5 text-indigo-400" />
                  {isEn ? "API Token (Bearer)" : "توکن امنیتی API Token (Bearer)"}
                </label>
                <input
                  type="text"
                  value={apiToken}
                  onChange={(e) => setApiToken(e.target.value)}
                  dir="ltr"
                  placeholder="Enter API token (Settings > Security > API Token)"
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl px-4 py-2.5 text-xs font-mono text-gray-300 placeholder-gray-600 focus:outline-none focus:border-indigo-500 transition-all"
                />
                <p className="text-[10px] text-gray-500 mt-1 leading-normal">
                  {isEn 
                    ? "Get this from Settings > Security > API Token in your panel. It bypasses form logins and completely avoids Cloudflare & WAF block issues!" 
                    : "این توکن را از بخش «تنظیمات پنل > امنیت > توکن API» کپی کنید. این روش فرم ورود را به کلی دور زده و خطاهای فایروال یا کلادفلر را حل می‌کند."}
                </p>
              </div>
            )}
          </div>

          {/* Right Column: Inbound / Security Mapping */}
          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <div className="flex justify-between items-center mb-2">
                  <label className="block text-xs font-bold text-gray-400">
                    {isEn ? "Inbound Tag" : "تگ اینباند (Inbound Tag)"}
                  </label>
                  <button
                    type="button"
                    onClick={handleFetchInbounds}
                    disabled={isFetchingInbounds}
                    className="text-[10px] text-indigo-400 hover:text-indigo-300 transition-all flex items-center space-x-1 space-x-reverse disabled:opacity-50"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ml-1 ${isFetchingInbounds ? "animate-spin" : ""}`} />
                    <span>{isFetchingInbounds ? (isEn ? "Loading..." : "در حال دریافت...") : (isEn ? "Fetch Inbounds" : "دریافت اینباندها")}</span>
                  </button>
                </div>

                {inbounds.length > 0 ? (
                  <div className="space-y-2">
                    <select
                      value={inboundTag}
                      onChange={(e) => {
                        const val = e.target.value;
                        setInboundTag(val);
                        // Auto detect port if possible
                        if (val !== "__custom__") {
                          const selected = inbounds.find(inb => inb.tag === val);
                          if (selected && selected.port) {
                            setSyncPort(selected.port);
                          }
                        }
                      }}
                      className="w-full bg-gray-950 border border-gray-800 rounded-xl px-4 py-2.5 text-xs text-gray-300 focus:outline-none focus:border-indigo-500 transition-all font-mono"
                    >
                      {inbounds.map((inb) => (
                        <option key={inb.id} value={inb.tag}>
                          {inb.tag} ({inb.protocol} - Port {inb.port}) {inb.remark ? `- ${inb.remark}` : ""}
                        </option>
                      ))}
                      <option value="__custom__">
                        {isEn ? "-- Enter custom tag manually --" : "-- ورود دستی تگ دلخواه --"}
                      </option>
                    </select>

                    {inboundTag === "__custom__" && (
                      <input
                        type="text"
                        onChange={(e) => setInboundTag(e.target.value)}
                        placeholder="vless-ws"
                        className="w-full bg-gray-950 border border-gray-800 rounded-xl px-4 py-2 text-xs font-mono text-gray-300 placeholder-gray-600 focus:outline-none focus:border-indigo-500 transition-all"
                      />
                    )}
                  </div>
                ) : (
                  <input
                    type="text"
                    value={inboundTag}
                    onChange={(e) => setInboundTag(e.target.value)}
                    placeholder="vless-ws"
                    className="w-full bg-gray-950 border border-gray-800 rounded-xl px-4 py-2.5 text-xs font-mono text-gray-300 placeholder-gray-600 focus:outline-none focus:border-indigo-500 transition-all"
                  />
                )}
                
                {fetchInboundsError && (
                  <p className="text-[10px] text-rose-400 mt-1 leading-tight">
                    {fetchInboundsError}
                  </p>
                )}
                
                <p className="text-[9.5px] text-gray-500 mt-1">
                  {isEn ? "Matches your inbound config tag." : "نام تگ کانفیگ شما در پنل (خالی = همه)"}
                </p>
              </div>

              <div>
                <label className="block text-xs font-bold text-gray-400 mb-2">
                  {isEn ? "Security" : "امنیت (Security)"}
                </label>
                <select
                  value={security}
                  onChange={(e) => setSecurity(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl px-4 py-2.5 text-xs text-gray-300 focus:outline-none focus:border-indigo-500 transition-all"
                >
                  <option value="same">same</option>
                  <option value="tls">tls</option>
                  <option value="none">none</option>
                  <option value="reality">reality</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="sm:col-span-2">
                <label className="block text-xs font-bold text-gray-400 mb-2">
                  {isEn ? "Host Remark Prefix" : "پیشوند نام (Remark Prefix)"}
                </label>
                <input
                  type="text"
                  value={remarkPrefix}
                  onChange={(e) => setRemarkPrefix(e.target.value)}
                  placeholder="Cloudflare-Clean"
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl px-4 py-2.5 text-xs text-gray-300 placeholder-gray-600 focus:outline-none focus:border-indigo-500 transition-all"
                />
                <p className="text-[10px] text-gray-500 mt-1">
                  {isEn 
                    ? "Prefix-IP format." 
                    : "نام هاست به صورت «پیشوند-آی‌پی» ذخیره می‌شود."}
                </p>
              </div>
              <div>
                <label className="block text-xs font-bold text-gray-400 mb-2">
                  {isEn ? "Inbound Port" : "پورت اینباند"}
                </label>
                <input
                  type="number"
                  value={syncPort}
                  onChange={(e) => setSyncPort(Number(e.target.value))}
                  placeholder="443"
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl px-4 py-2.5 text-xs text-gray-300 font-mono focus:outline-none focus:border-indigo-500 transition-all text-center"
                />
                <p className="text-[10px] text-gray-500 mt-1 text-center">
                  {isEn ? "Port" : "پورت هدف"}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Sync Status Banner */}
        {syncStatus && (
          <div className="mt-6 space-y-4">
            <div className={`p-4 rounded-2xl border flex items-start space-x-3 space-x-reverse ${
              syncStatus.success 
                ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400" 
                : "bg-rose-500/10 border-rose-500/30 text-rose-400"
            }`}>
              {syncStatus.success ? (
                <Check className="w-5 h-5 ml-1.5 flex-shrink-0" />
              ) : (
                <AlertCircle className="w-5 h-5 ml-1.5 flex-shrink-0" />
              )}
              <span className="text-xs font-semibold leading-normal">{syncStatus.message}</span>
            </div>

            {/* Results breakdown */}
            {syncStatus.results && syncStatus.results.length > 0 && (
              <div className="bg-gray-950 p-4 rounded-2xl border border-gray-850">
                <h5 className="text-xs font-bold text-gray-300 mb-3">
                  {isEn ? "Sync Details:" : "جزئیات ثبت در پنل:"}
                </h5>
                <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                  {syncStatus.results.map((res, i) => (
                    <div key={i} className="text-[10px] font-mono p-2 rounded-lg bg-gray-900 border border-gray-800">
                      <div className="flex justify-between">
                        <span className={res.success ? "text-emerald-400" : "text-rose-400"}>
                          {res.ip} - {res.success ? "OK" : "FAILED"}
                        </span>
                      </div>
                      {res.error && <div className="text-rose-400/80 mt-1">{res.error}</div>}
                      {res.workingPath && (
                        <div className="text-emerald-500 font-semibold mt-1">
                          Working Path: {res.workingPath}
                        </div>
                      )}
                      {/* Always show diagnostics if they exist, to debug success paths */}
                      {res.diagnostics && res.diagnostics.length > 0 && (
                        <div className="text-gray-400 mt-2 pl-2 border-r border-gray-700 space-y-1">
                          {res.diagnostics.map((d, di) => {
                            const isWorking = res.workingPath === d.path;
                            return (
                              <div key={di} className={`p-1 rounded ${isWorking ? "bg-emerald-950/30 border border-emerald-900/40 text-emerald-300" : "text-gray-500"}`}>
                                <div className="font-semibold">
                                  Path: {d.path} | {d.error ? `Error: ${d.error}` : `Status ${d.status}`} {isWorking && "⭐"}
                                </div>
                                {d.snippet && (
                                  <div className="text-gray-300 break-all bg-gray-950 p-1 rounded mt-0.5 border border-gray-800">
                                    Resp: {d.snippet}
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Actions button row */}
        <div className="mt-6 flex justify-end">
          <button
            onClick={handleSyncToPanel}
            disabled={isSyncing || ipsToSync.length === 0}
            className="w-full sm:w-auto bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white font-bold text-sm px-8 py-3.5 rounded-2xl transition-all shadow-md flex items-center justify-center space-x-2 space-x-reverse"
          >
            {isSyncing ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin ml-2" />
                <span>{isEn ? "Syncing Clean IPs..." : "در حال ثبت آی‌پی‌ها در پنل..."}</span>
              </>
            ) : (
              <>
                <CloudLightning className="w-4 h-4 ml-2" />
                <span>{isEn ? "Sync Clean IPs to Panel" : "ثبت آنی آی‌پی‌های تمیز در پنل سنایی"}</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
