import React from 'react';
import { Copy } from 'lucide-react';
import { Card, Button, TextArea, Input, Select } from '../ui';

const JWTTool: React.FC = () => {
    const [rawToken, setRawToken] = React.useState('');
    const [header, setHeader] = React.useState('');
    const [payload, setPayload] = React.useState('');
    const [secretKey, setSecretKey] = React.useState('');
    const [alg, setAlg] = React.useState('HS256');
    const [noneAlgToken, setNoneAlgToken] = React.useState('');

    const handleCopy = (text: string) => {
        navigator.clipboard.writeText(text);
    };

    const decodeToken = (token: string) => {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) {
                setHeader('Invalid JWT - must have 3 parts');
                setPayload('');
                return;
            }

            const decodedHeader = JSON.parse(atob(parts[0]));
            const decodedPayload = JSON.parse(atob(parts[1]));

            setHeader(JSON.stringify(decodedHeader, null, 2));
            setPayload(JSON.stringify(decodedPayload, null, 2));

            // None algorithm attack
            if (alg === 'none') {
                const modifiedHeader = { ...decodedHeader, alg: 'none' };
                const noneHeader = btoa(JSON.stringify(modifiedHeader));
                setNoneAlgToken(`${noneHeader}.${parts[1]}.`);
            }
        } catch (err) {
            setHeader('Invalid JWT format');
            setPayload('');
        }
    };

    React.useEffect(() => {
        if (rawToken) {
            decodeToken(rawToken);
        }
    }, [rawToken, alg]);

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-bold text-white mb-2">JSON Web Token (JWT)</h2>
                <p className="text-gray-400 text-sm">
                    Decode, verify, and manipulate JWT tokens. Test for common vulnerabilities like the "none" algorithm attack.
                </p>
            </div>

            <div className="space-y-4">
                <TextArea
                    label="JWT Token"
                    value={rawToken}
                    onChange={(e) => setRawToken(e.target.value)}
                    className="h-32"
                    placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ..."
                />

                <div className="grid grid-cols-2 gap-4">
                    <Input
                        label="Secret Key"
                        type="text"
                        value={secretKey}
                        onChange={(e) => setSecretKey(e.target.value)}
                        placeholder="your-secret-key"
                    />
                    <Select
                        label="Algorithm"
                        value={alg}
                        onChange={setAlg}
                        options={[
                            { value: 'HS256', label: 'HS256' },
                            { value: 'none', label: 'None (Attack)' },
                        ]}
                    />
                </div>

                {alg === 'none' && noneAlgToken && (
                    <Card className="bg-red-500/10 border-red-500/20">
                        <div className="flex items-center justify-between mb-2">
                            <span className="text-sm font-medium text-red-400">JWT without Signature (None Attack)</span>
                            <Button
                                size="sm"
                                variant="outline"
                                onClick={() => handleCopy(noneAlgToken)}
                                icon={<Copy size={16} />}
                                className="text-red-400 border-red-400 hover:bg-red-500/10"
                            />
                        </div>
                        <code className="text-xs text-red-300 break-all block">{noneAlgToken}</code>
                    </Card>
                )}

                <div>
                    <div className="flex items-center justify-between mb-2">
                        <label className="text-sm font-medium text-gray-300">Header (Algorithm & Token Type)</label>
                        <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => handleCopy(header)}
                            disabled={!header}
                            icon={<Copy size={16} />}
                        />
                    </div>
                    <TextArea
                        value={header}
                        readOnly
                        className="h-24 text-[#a2ff00]"
                        placeholder='{\n  "alg": "HS256",\n  "typ": "JWT"\n}'
                    />
                </div>

                <div>
                    <div className="flex items-center justify-between mb-2">
                        <label className="text-sm font-medium text-gray-300">Payload (JWT Claims)</label>
                        <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => handleCopy(payload)}
                            disabled={!payload}
                            icon={<Copy size={16} />}
                        />
                    </div>
                    <TextArea
                        value={payload}
                        readOnly
                        className="h-48 text-[#a2ff00]"
                        placeholder='{\n  "sub": "1234567890",\n  "name": "John Doe",\n  "iat": 1516239022\n}'
                    />
                </div>
            </div>
        </div>
    );
};

export default JWTTool;
