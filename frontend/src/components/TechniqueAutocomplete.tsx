import { useState, useRef, useEffect, useMemo } from 'react';
import { useMitre } from '../contexts/MitreContext';

interface TechniqueAutocompleteProps {
  value: string;
  onChange: (value: string) => void;
  onSelect?: (techniqueId: string, techniqueName: string) => void;
  placeholder?: string;
  className?: string;
}

export function TechniqueAutocomplete({
  value,
  onChange,
  onSelect,
  placeholder = 'Search techniques (e.g., T1059 or "powershell")',
  className = '',
}: TechniqueAutocompleteProps) {
  const { techniques } = useMitre();
  const [isOpen, setIsOpen] = useState(false);
  const [highlightedIndex, setHighlightedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Convert techniques object to sorted array
  const techniqueList = useMemo(() => {
    return Object.values(techniques)
      .filter((t) => !t.deprecated)
      .sort((a, b) => a.id.localeCompare(b.id));
  }, [techniques]);

  // Filter techniques based on input
  const filteredTechniques = useMemo(() => {
    if (!value.trim()) return [];

    const searchTerm = value.toLowerCase();
    return techniqueList
      .filter((technique) => {
        const idMatch = technique.id.toLowerCase().includes(searchTerm);
        const nameMatch = technique.name.toLowerCase().includes(searchTerm);
        return idMatch || nameMatch;
      })
      .slice(0, 15); // Limit to 15 results
  }, [value, techniqueList]);

  // Reset highlighted index when results change
  useEffect(() => {
    setHighlightedIndex(0);
  }, [filteredTechniques]);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(event.target as Node) &&
        inputRef.current &&
        !inputRef.current.contains(event.target as Node)
      ) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleSelect = (technique: { id: string; name: string }) => {
    onChange(technique.id);
    onSelect?.(technique.id, technique.name);
    setIsOpen(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (!isOpen || filteredTechniques.length === 0) {
      if (e.key === 'ArrowDown' && filteredTechniques.length > 0) {
        setIsOpen(true);
      }
      return;
    }

    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setHighlightedIndex((prev) =>
          prev < filteredTechniques.length - 1 ? prev + 1 : prev
        );
        break;
      case 'ArrowUp':
        e.preventDefault();
        setHighlightedIndex((prev) => (prev > 0 ? prev - 1 : 0));
        break;
      case 'Enter':
        e.preventDefault();
        if (filteredTechniques[highlightedIndex]) {
          handleSelect(filteredTechniques[highlightedIndex]);
        }
        break;
      case 'Escape':
        setIsOpen(false);
        break;
    }
  };

  // Scroll highlighted item into view
  useEffect(() => {
    if (isOpen && dropdownRef.current) {
      const highlightedElement = dropdownRef.current.querySelector(
        `[data-index="${highlightedIndex}"]`
      );
      highlightedElement?.scrollIntoView({ block: 'nearest' });
    }
  }, [highlightedIndex, isOpen]);

  return (
    <div className="relative flex-1">
      <input
        ref={inputRef}
        type="text"
        value={value}
        onChange={(e) => {
          onChange(e.target.value);
          setIsOpen(true);
        }}
        onFocus={() => {
          if (value.trim() && filteredTechniques.length > 0) {
            setIsOpen(true);
          }
        }}
        onKeyDown={handleKeyDown}
        placeholder={placeholder}
        className={`w-full px-4 py-3 bg-void-900 border border-void-700 text-white placeholder-gray-500 focus:ring-2 focus:ring-matrix-500/50 focus:border-matrix-500/50 ${className}`}
      />

      {/* Dropdown */}
      {isOpen && filteredTechniques.length > 0 && (
        <div
          ref={dropdownRef}
          className="absolute z-50 w-full mt-1 bg-void-900 border border-void-600 shadow-xl max-h-80 overflow-y-auto"
          style={{
            clipPath:
              'polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px))',
          }}
        >
          {filteredTechniques.map((technique, index) => (
            <button
              key={technique.id}
              data-index={index}
              onClick={() => handleSelect(technique)}
              onMouseEnter={() => setHighlightedIndex(index)}
              className={`w-full text-left px-4 py-3 flex items-center gap-3 transition-colors ${
                index === highlightedIndex
                  ? 'bg-matrix-500/20 border-l-2 border-matrix-500'
                  : 'hover:bg-void-800 border-l-2 border-transparent'
              }`}
            >
              <span
                className={`font-mono text-sm px-2 py-0.5 rounded ${
                  index === highlightedIndex
                    ? 'bg-matrix-500/30 text-matrix-400'
                    : 'bg-void-800 text-matrix-500'
                }`}
              >
                {technique.id}
              </span>
              <span
                className={`text-sm truncate ${
                  index === highlightedIndex ? 'text-white' : 'text-gray-400'
                }`}
              >
                {technique.name}
              </span>
              {technique.is_subtechnique && (
                <span className="text-xs text-gray-600 font-mono ml-auto">
                  SUB
                </span>
              )}
            </button>
          ))}
        </div>
      )}

      {/* No results message */}
      {isOpen && value.trim() && filteredTechniques.length === 0 && (
        <div
          className="absolute z-50 w-full mt-1 bg-void-900 border border-void-600 px-4 py-3"
          style={{
            clipPath:
              'polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px))',
          }}
        >
          <span className="text-sm text-gray-500 font-mono">
            NO_MATCHING_TECHNIQUES
          </span>
        </div>
      )}
    </div>
  );
}
