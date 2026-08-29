import { useState } from "react";

export default function ResultTable({ entry }) {
  const [expanded, setExpanded] = useState(false);
  const result = entry.result?.result || entry.result;
  const rows = Array.isArray(result?.rows) ? result.rows : [];
  if (!rows.length) return null;

  const total = Number(result.row_count) || rows.length;
  const visible = expanded ? rows : rows.slice(0, 5);
  const columns = Object.keys(rows[0]).slice(0, 7);

  return (
    <div className="result-box">
      <table>
        <thead>
          <tr>{columns.map((column) => <th key={column}>{column}</th>)}</tr>
        </thead>
        <tbody>
          {visible.map((row, index) => (
            <tr key={`${entry.id}-${index}`}>
              {columns.map((column) => (
                <td className={row[column] === "***REDACTED***" ? "redacted" : ""} key={column}>
                  {String(row[column] ?? "")}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      <div className="result-actions">
        <span className="result-count">Showing {visible.length.toLocaleString()} of {total.toLocaleString()} rows</span>
        {total > 5 && (
          <button className="result-expand" onClick={() => setExpanded((value) => !value)}>
            {expanded ? "Collapse rows" : `Show all ${total.toLocaleString()} rows`}
          </button>
        )}
      </div>
    </div>
  );
}
