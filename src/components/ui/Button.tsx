import React from 'react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
    variant?: 'primary' | 'secondary' | 'ghost' | 'outline';
    size?: 'sm' | 'md' | 'lg';
    icon?: React.ReactNode;
}

export const Button: React.FC<ButtonProps> = ({
    children,
    variant = 'primary',
    size = 'md',
    icon,
    className = '',
    ...props
}) => {
    const variants = {
        primary: 'bg-[#a2ff00] text-[#05080d] font-bold hover:brightness-110 shadow-lg shadow-[#a2ff00]/20',
        secondary: 'bg-[#1a1f28] text-gray-300 border border-white/10 hover:bg-[#252a35] hover:text-white',
        ghost: 'bg-transparent text-gray-400 hover:text-white hover:bg-white/5',
        outline: 'bg-transparent text-gray-400 border border-white/10 hover:text-white hover:border-[#a2ff00]/50',
    };

    const sizes = {
        sm: 'px-3 py-1.5 text-xs',
        md: 'px-4 py-2 text-sm',
        lg: 'px-6 py-3 text-base',
    };

    return (
        <button
            className={`
        inline-flex items-center justify-center gap-2 rounded-lg font-medium
        transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed
        ${variants[variant]}
        ${sizes[size]}
        ${className}
      `}
            {...props}
        >
            {icon && <span className="flex-shrink-0">{icon}</span>}
            {children}
        </button>
    );
};
