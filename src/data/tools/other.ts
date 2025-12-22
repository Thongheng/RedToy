import type { Tool } from '../../types';
import { createArg } from './common';

export const OTHER_TOOLS: Tool[] = [
    {
        id: 'scp',
        name: 'SCP',
        category: 'UTILITIES',
        subcategory: 'File Transfer',
        desc: 'Secure copy (remote file copy program).',
        authMode: 'required',
        generate: (v, args) => {
            return `scp -r ${v.filepath || '$FILEPATH'} ${v.username || '$USERNAME'}@${v.target || '$TARGET'}:/home/${v.username || '$DESTINATION'}/`;
        }
    },
    {
        id: 'bash',
        name: 'Bash',
        category: 'UTILITIES',
        subcategory: 'File Transfer',
        desc: 'Bash built-in file transfer',
        authMode: 'none',
        args: [
        ],
        generate: (v, args) => {
            return `# Sender
nc -lvnp 8000 < ${v.filepath || '$FILEPATH'}

# Receiver
nc -q 0 ${v.target || '$TARGET'} 8000 > ${v.filepath || '$FILEPATH'}`;
        }
    },
    {
        id: 'impacket-smb',
        name: 'Impacket SMB Server',
        category: 'UTILITIES',
        subcategory: 'File Transfer',
        desc: 'Impacket SMB Server for file sharing.',
        authMode: 'none',
        generate: (v, args) => {
            return `sudo impacket-smbserver share -smb2support .`;
        }
    },

];
