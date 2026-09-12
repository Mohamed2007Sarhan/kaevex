import React from 'react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  children: React.ReactNode;
}

export const Button: React.FC<ButtonProps> = ({
  variant = 'secondary',
  size = 'md',
  children,
  className = '',
  style,
  ...props
}) => {
  // Setup styles inline for full control without TailwindCSS
  const getStyles = () => {
    let bg = 'hsl(var(--bg-tertiary))';
    let color = 'hsl(var(--text-primary))';
    let border = '1px solid hsl(var(--border-primary))';
    let padding = '0.5rem 1rem';
    let fontSize = '0.875rem';

    if (variant === 'primary') {
      bg = 'hsl(var(--accent-color))';
      color = 'white';
      border = '1px solid transparent';
    } else if (variant === 'danger') {
      bg = 'hsl(var(--color-critical))';
      color = 'white';
      border = '1px solid transparent';
    } else if (variant === 'ghost') {
      bg = 'transparent';
      border = '1px solid transparent';
      color = 'hsl(var(--text-secondary))';
    }

    if (size === 'sm') {
      padding = '0.35rem 0.75rem';
      fontSize = '0.75rem';
    } else if (size === 'lg') {
      padding = '0.75rem 1.5rem';
      fontSize = '1rem';
    }

    return {
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center',
      gap: '0.5rem',
      fontWeight: 500,
      borderRadius: 'var(--radius-sm)',
      backgroundColor: bg,
      color: color,
      border: border,
      padding: padding,
      fontSize: fontSize,
      cursor: 'pointer',
      transition: 'all 0.15s ease',
      ...style
    };
  };

  return (
    <button
      style={getStyles()}
      className={`custom-btn ${className}`}
      {...props}
    >
      {children}
    </button>
  );
};
