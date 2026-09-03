import type { RawHeader } from '../types';

export function RawHeaders({ headers }: { headers: readonly RawHeader[] }): React.JSX.Element {
  return (
    <details className="raw">
      <summary>Ver os {headers.length} headers da resposta</summary>
      <table className="raw__table">
        <caption className="visually-hidden">Headers da resposta HTTP, na ordem em que chegaram</caption>
        <thead>
          <tr>
            <th scope="col">Header</th>
            <th scope="col">Valor</th>
          </tr>
        </thead>
        <tbody>
          {headers.map((header, index) => (
            // Duplicate header names are legal, so the name alone is not a key.
            <tr key={`${header.name}-${index}`}>
              <th scope="row">{header.name}</th>
              <td>{header.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </details>
  );
}
