import React from 'react';

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
    label?: string;
    icon?: React.ReactNode;
    error?: string;
}

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
    ({ label, icon, error, className = '', ...props }, ref) => {
        return (
            <div className="w-full">
                {label && (
                    <label className="block text-xs font-bold text-gray-400 uppercase tracking-wider mb-2">
                        {label}
                    </label>
                )}
                <div className="relative">
                    {icon && (
                        <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500">
                            {icon}
                        </span>
                    )}
                    <input
                        ref={ref}
                        className={`
              w-full bg-[#0d1117] border border-white/10 rounded-lg 
              px-4 py-2.5 text-sm text-white font-mono
              placeholder:text-gray-600
              focus:border-[#a2ff00]/50 focus:outline-none focus:ring-1 focus:ring-[#a2ff00]/20
              transition-all duration-200
              ${icon ? 'pl-10' : ''}
              ${error ? 'border-red-500/50' : ''}
              ${className}
            `}
                        {...props}
                    />
                </div>
                {error && <p className="text-red-500 text-xs mt-1">{error}</p>}
            </div>
        );
    }
);

Input.displayName = 'Input';

interface TextAreaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
    label?: string;
    error?: string;
}

export const TextArea = React.forwardRef<HTMLTextAreaElement, TextAreaProps>(
    ({ label, error, className = '', ...props }, ref) => {
        return (
            <div className="w-full">
                {label && (
                    <label className="block text-xs font-bold text-gray-400 uppercase tracking-wider mb-2">
                        {label}
                    </label>
                )}
                <textarea
                    ref={ref}
                    className={`
              w-full bg-[#0d1117] border border-white/10 rounded-lg 
              px-4 py-2.5 text-sm text-white font-mono
              placeholder:text-gray-600
              focus:border-[#a2ff00]/50 focus:outline-none focus:ring-1 focus:ring-[#a2ff00]/20
              transition-all duration-200 resize-y
              ${error ? 'border-red-500/50' : ''}
              ${className}
            `}
                    {...props}
                />
                {error && <p className="text-red-500 text-xs mt-1">{error}</p>}
            </div>
        );
    }
);

TextArea.displayName = 'TextArea';

interface SelectOption {
    label: string;
    value: string;
    group?: string;
}

interface SelectProps {
    label?: string;
    options: SelectOption[];
    value: string;
    onChange: (value: string) => void;
    placeholder?: string;
    className?: string;
}

export const Select: React.FC<SelectProps> = ({
    label,
    options,
    value,
    onChange,
    placeholder = 'Select...',
    className = '',
}) => {
    return (
        <div className={`w-full ${className}`}>
            {label && (
                <label className="block text-xs font-bold text-gray-400 uppercase tracking-wider mb-2">
                    {label}
                </label>
            )}
            <select
                value={value}
                onChange={(e) => onChange(e.target.value)}
                className="w-full bg-[#0d1117] border border-white/10 rounded-lg px-4 py-2.5 text-sm text-white font-mono cursor-pointer focus:border-[#a2ff00]/50 focus:outline-none focus:ring-1 focus:ring-[#a2ff00]/20 transition-all duration-200 appearance-none"
                style={{
                    backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 20 20'%3E%3Cpath stroke='%236b7280' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.5' d='m6 8 4 4 4-4'/%3E%3C/svg%3E")`,
                    backgroundPosition: 'right 0.5rem center',
                    backgroundRepeat: 'no-repeat',
                    backgroundSize: '1.5em 1.5em',
                    paddingRight: '2.5rem',
                }}
            >
                <option value="" disabled>{placeholder}</option>
                {options.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                        {opt.label}
                    </option>
                ))}
            </select>
        </div>
    );
};

interface TagProps {
    children: React.ReactNode;
    color?: 'green' | 'blue' | 'red' | 'orange' | 'purple' | 'cyan' | 'yellow' | 'gray';
    className?: string;
}

const tagColors: Record<string, string> = {
    green: 'bg-green-500/10 text-green-500 border-green-500/20',
    blue: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
    red: 'bg-red-500/10 text-red-500 border-red-500/20',
    orange: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
    purple: 'bg-purple-500/10 text-purple-500 border-purple-500/20',
    cyan: 'bg-cyan-500/10 text-cyan-500 border-cyan-500/20',
    yellow: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
    gray: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
};

export const Tag: React.FC<TagProps> = ({ children, color = 'gray', className = '' }) => {
    return (
        <span
            className={`
        inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border
        ${tagColors[color] || tagColors.gray}
        ${className}
      `}
        >
            {children}
        </span>
    );
};

import { Button } from './Button';
export { Button };
export { PayloadBlock } from './PayloadBlock';

interface DropdownItem {
    key: string;
    label: string;
    icon?: React.ReactNode;
}

interface DropdownProps {
    trigger: React.ReactNode;
    items: DropdownItem[];
    onSelect: (key: string) => void;
}

export const Dropdown: React.FC<DropdownProps> = ({ trigger, items, onSelect }) => {
    const [isOpen, setIsOpen] = React.useState(false);

    return (
        <div className="relative inline-block">
            <div onClick={() => setIsOpen(!isOpen)}>{trigger}</div>
            {isOpen && (
                <>
                    <div className="fixed inset-0 z-40" onClick={() => setIsOpen(false)} />
                    <div className="absolute right-0 mt-2 w-48 bg-[#0d1117] border border-white/10 rounded-lg shadow-xl z-50 overflow-hidden">
                        {items.map((item) => (
                            <button
                                key={item.key}
                                onClick={() => {
                                    onSelect(item.key);
                                    setIsOpen(false);
                                }}
                                className="w-full px-4 py-2.5 text-left text-sm text-gray-300 hover:bg-[#a2ff00]/10 hover:text-[#a2ff00] flex items-center gap-2 transition-colors"
                            >
                                {item.icon}
                                {item.label}
                            </button>
                        ))}
                    </div>
                </>
            )}
        </div>
    );
};

interface CardProps {
    children: React.ReactNode;
    className?: string;
    hover?: boolean;
}

export const Card: React.FC<CardProps> = ({ children, className = '', hover = false }) => {
    return (
        <div
            className={`
        bg-[#0d1117] border border-white/5 rounded-2xl p-6
        ${hover ? 'hover:border-[#a2ff00]/20 hover:shadow-lg hover:shadow-[#a2ff00]/5 transition-all duration-300' : ''}
        ${className}
      `}
        >
            {children}
        </div>
    );
};


import { Tabs, TabNav } from './Tabs';

export { Tabs, TabNav };
export default { Input, TextArea, Select, Tag, Button, Dropdown, Card, Tabs, TabNav };
