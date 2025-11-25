import { ReferenceItem } from '../types';

export const REFERENCES: ReferenceItem[] = [
    {
        id: 'ired_team',
        name: 'Red Teaming Notes',
        category: 'REF',
        subcategory: 'Red Teaming',
        desc: 'A comprehensive collection of Red Teaming notes, tactics, and experiments by spotheplanet.',
        url: 'https://www.ired.team/'
    },
    {
        id: 'internal_all_the_things',
        name: 'Internal All The Things',
        category: 'REF',
        subcategory: 'Red Teaming',
        desc: 'A comprehensive collection of Active Directory and Internal Pentest Cheatsheets',
        url: 'https://swisskyrepo.github.io/InternalAllTheThings/'
    },
    {
        id: 'AD_Enums_Attack',
        name: 'AD Enums & Attack',
        category: 'REF',
        subcategory: 'Red Teaming',
        desc: 'A collection of cheatsheets for attacking AD — from enumeration and authentication attacks to ACL abuse, delegation, and lateral movement techniques.',
        url: 'https://adminions.ca/books/active-directory-enumeration-and-exploitation'
    },
    {
        id: 'gtfobins',
        name: 'GTFOBins',
        category: 'REF',
        subcategory: 'Linux & Windows',
        desc: 'Curated list of Unix binaries that can be used to bypass local security restrictions.',
        url: 'https://gtfobins.github.io/'
    },
    {
        id: 'wadcoms',
        name: 'WADComs',
        category: 'REF',
        subcategory: 'Linux & Windows',
        desc: 'WADComs is an interactive cheat sheet, containing a curated list of offensive security tools and their respective commands, to be used against Windows/AD environments.',
        url: 'https://wadcoms.github.io/'
    },
    {
        id: 'lolbas',
        name: 'LOLBAS',
        category: 'REF',
        subcategory: 'Linux & Windows',
        desc: 'Living Off The Land Binaries, Scripts and Libraries for Windows.',
        url: 'https://lolbas-project.github.io/'
    },
    {
        id: 'payloads_all_things',
        name: 'Payloads All The Things',
        category: 'REF',
        subcategory: 'Application',
        desc: 'A list of useful payloads and bypasses for Web Application Security.',
        url: 'https://swisskyrepo.github.io/PayloadsAllTheThings/'
    },
    {
        id: 'hacktricks',
        name: 'HackTricks',
        category: 'REF',
        subcategory: 'General',
        desc: 'A massive wiki of All in One hacking tricks and techniques',
        url: 'https://book.hacktricks.wiki/en/index.html'
    },
    {
        id: 'cyberchef',
        name: 'CyberChef',
        category: 'REF',
        subcategory: 'General',
        desc: 'A web app for encryption, encoding, compression and data analysis.',
        url: 'https://gchq.github.io/CyberChef/'
    },
    {
        id: 'revshell',
        name: 'RevShell',
        category: 'REF',
        subcategory: 'General',
        desc: 'Reverse Shell Generator',
        url: 'https://www.revshells.com/'
    },
    {
        id: 'cipher_identifier',
        name: 'Cipher Identifier',
        category: 'REF',
        subcategory: 'General',
        desc: 'Cipher Identifier is a web app for encryption, encoding, compression and data analysis.',
        url: 'https://www.dcode.fr/cipher-identifier'
    },
    {
        id: 'ctf_guide',
        name: 'CTF Guide',
        category: 'REF',
        subcategory: 'General',
        desc: 'A big collection of my notes for Capture The Flag (CTF) challenges and Hacking Techniques',
        url: 'https://book.jorianwoltjer.com/'
    }
];