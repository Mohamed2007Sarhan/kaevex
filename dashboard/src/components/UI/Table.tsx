import React from 'react';
import { FolderOpen } from 'lucide-react';

interface Column<T> {
  header: string;
  accessor: (item: T) => React.ReactNode;
}

interface TableProps<T> {
  columns: Column<T>[];
  data: T[];
  isLoading?: boolean;
  emptyMessage?: string;
}

export function Table<T>({
  columns,
  data,
  isLoading = false,
  emptyMessage = 'No records found.'
}: TableProps<T>) {
  if (isLoading) {
    return (
      <div className="table-container">
        <table className="enterprise-table">
          <thead>
            <tr>
              {columns.map((col, index) => (
                <th key={index}>{col.header}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[1, 2, 3, 4].map((rowIdx) => (
              <tr key={rowIdx}>
                {columns.map((col, colIdx) => (
                  <td key={colIdx}>
                    <div className="skeleton" style={{ height: '1.2rem', width: '70%', margin: '0.2rem 0' }}></div>
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  if (data.length === 0) {
    return (
      <div className="table-container" style={{ padding: '3rem 1.5rem', textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: 'hsl(var(--text-secondary))', gap: '0.5rem' }}>
        <FolderOpen size={28} opacity={0.4} />
        <div style={{ fontSize: '0.875rem', fontWeight: 500 }}>{emptyMessage}</div>
      </div>
    );
  }

  return (
    <div className="table-container">
      <table className="enterprise-table">
        <thead>
          <tr>
            {columns.map((col, index) => (
              <th key={index}>{col.header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((item, rowIdx) => (
            <tr key={rowIdx}>
              {columns.map((col, colIdx) => (
                <td key={colIdx}>{col.accessor(item)}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
