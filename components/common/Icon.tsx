
import React from 'react';
import * as icons from 'lucide-react';

interface IconProps {
  name: keyof typeof icons;
  color?: string;
  size?: number | string;
  className?: string;
}

const Icon: React.FC<IconProps> = ({ name, color, size, className }) => {
  // @ts-ignore - dynamic access to icons
  const LucideIcon = icons[name] as React.ElementType;

  if (!LucideIcon) {
    console.warn(`Icon "${name}" not found in lucide-react`);
    return null;
  }

  return <LucideIcon color={color} size={size} className={className} />;
};

export default Icon;