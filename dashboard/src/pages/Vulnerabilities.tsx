import React, { useState } from 'react';
import { AlertOctagon, Package, Shield, RefreshCw, Search } from 'lucide-react';
import { Card } from '../components/UI/Card';
import { Button } from '../components/UI/Button';
import { api } from '../api/client';

interface VulnerabilitiesProps {
  liveData: any;
  addToast: any;
  vulnerabilities?: any;
  setVulnerabilities?: any;
}

export default function Vulnerabilities({ liveData, addToast }: VulnerabilitiesProps) {
  const { cveReport, hgComponents } = liveData;
  const [searchTerm, setSearchTerm] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 20;

  const handleRunScan = async () => {
    try {
      await api.hostguardForceScan();
      addToast('CVE Scan initiated successfully', 'success');
    } catch (err) {
      addToast('Failed to initiate scan', 'error');
    }
  };

  const getRiskBadge = (level: string) => {
    switch(level?.toLowerCase()) {
      case 'critical': return <span className="px-2 py-1 text-xs rounded-full bg-red-100 text-red-800">Critical</span>;
      case 'high': return <span className="px-2 py-1 text-xs rounded-full bg-orange-100 text-orange-800">High</span>;
      case 'medium': return <span className="px-2 py-1 text-xs rounded-full bg-yellow-100 text-yellow-800">Medium</span>;
      case 'low': return <span className="px-2 py-1 text-xs rounded-full bg-blue-100 text-blue-800">Low</span>;
      default: return <span className="px-2 py-1 text-xs rounded-full bg-gray-100 text-gray-800">{level || 'Unknown'}</span>;
    }
  };

  const getStatusBadge = (status: string) => {
    if (status?.toLowerCase() === 'success' || status?.toLowerCase() === 'remediated') {
      return <span className="px-2 py-1 text-xs rounded-full bg-green-100 text-green-800">{status}</span>;
    }
    if (status?.toLowerCase() === 'failed') {
      return <span className="px-2 py-1 text-xs rounded-full bg-red-100 text-red-800">{status}</span>;
    }
    return <span className="px-2 py-1 text-xs rounded-full bg-gray-100 text-gray-800">{status}</span>;
  };

  const renderCVEList = (cveList: string[]) => {
    if (!cveList || cveList.length === 0) return '-';
    const firstTwo = cveList.slice(0, 2);
    const remainder = cveList.length - 2;
    return (
      <div className="flex space-x-1 items-center">
        {firstTwo.map(cve => <span key={cve} className="text-xs font-mono bg-gray-100 px-1 py-0.5 rounded border">{cve}</span>)}
        {remainder > 0 && <span className="text-xs text-gray-500">+{remainder} more</span>}
      </div>
    );
  };

  const filteredComponents = (hgComponents || [])
    .filter((c: any) => c.name?.toLowerCase().includes(searchTerm.toLowerCase()))
    .sort((a: any, b: any) => (b.needs_cve_check ? 1 : 0) - (a.needs_cve_check ? 1 : 0));

  const totalPages = Math.ceil(filteredComponents.length / itemsPerPage);
  const currentComponents = filteredComponents.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900">Vulnerability Management</h1>
        <Button onClick={handleRunScan} className="flex items-center space-x-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded">
          <RefreshCw className="w-4 h-4" />
          <span>Run CVE Scan</span>
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="p-4 flex items-center space-x-4">
          <div className="p-3 bg-red-100 rounded-full text-red-600">
            <AlertOctagon className="w-6 h-6" />
          </div>
          <div>
            <div className="text-2xl font-bold text-gray-900">{cveReport?.total_cve_found?.toLocaleString() || 0}</div>
            <div className="text-sm text-gray-500">Total CVEs Found</div>
          </div>
        </Card>
        <Card className="p-4 flex items-center space-x-4">
          <div className="p-3 bg-blue-100 rounded-full text-blue-600">
            <Search className="w-6 h-6" />
          </div>
          <div>
            <div className="text-2xl font-bold text-gray-900">{cveReport?.total_checks_done?.toLocaleString() || 0}</div>
            <div className="text-sm text-gray-500">Checks Performed</div>
          </div>
        </Card>
        <Card className="p-4 flex items-center space-x-4">
          <div className="p-3 bg-green-100 rounded-full text-green-600">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="text-2xl font-bold text-gray-900">{cveReport?.remediations_applied?.toLocaleString() || 0}</div>
            <div className="text-sm text-gray-500">Auto-Remediated</div>
          </div>
        </Card>
        <Card className="p-4 flex items-center space-x-4">
          <div className="p-3 bg-purple-100 rounded-full text-purple-600">
            <Package className="w-6 h-6" />
          </div>
          <div>
            <div className="text-2xl font-bold text-gray-900">{(hgComponents?.length || 0).toLocaleString()}</div>
            <div className="text-sm text-gray-500">Tracked Components</div>
          </div>
        </Card>
      </div>

      <Card className="p-0 overflow-hidden">
        <div className="p-4 border-b bg-gray-50">
          <h2 className="text-lg font-bold text-gray-900">Recent Remediations</h2>
        </div>
        {cveReport?.recent_remediations && cveReport.recent_remediations.length > 0 ? (
          <div className="table-container"><table className="enterprise-table"><thead>
              <tr className="bg-gray-100 text-left text-sm text-gray-600 uppercase tracking-wider">
                <th className="p-3 font-semibold">Component</th>
                <th className="p-3 font-semibold">Risk Level</th>
                <th className="p-3 font-semibold">CVE IDs</th>
                <th className="p-3 font-semibold">Status</th>
                <th className="p-3 font-semibold">Remediated At</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {cveReport.recent_remediations.sort((a: any, b: any) => new Date(b.executed_at).getTime() - new Date(a.executed_at).getTime()).map((rem: any, i: number) => (
                <tr key={i} className="hover:bg-gray-50">
                  <td className="p-3 text-sm font-medium text-gray-900">{rem.component}</td>
                  <td className="p-3">{getRiskBadge(rem.risk_level)}</td>
                  <td className="p-3">{renderCVEList(rem.cve_list)}</td>
                  <td className="p-3">{getStatusBadge(rem.status)}</td>
                  <td className="p-3 text-sm text-gray-500">{new Date(rem.executed_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        ) : (
          <div className="p-8 text-center text-gray-500 flex flex-col items-center">
            <Shield className="w-12 h-12 mb-3 text-gray-300" />
            <p>No recent remediations found.</p>
          </div>
        )}
      </Card>

      <Card className="p-0 overflow-hidden">
        <div className="p-4 border-b bg-gray-50 flex justify-between items-center">
          <h2 className="text-lg font-bold text-gray-900">Software Inventory</h2>
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-gray-400" />
            <input 
              type="text" 
              placeholder="Search components..." 
              value={searchTerm}
              onChange={(e) => { setSearchTerm(e.target.value); setCurrentPage(1); }}
              className="pl-9 pr-4 py-2 border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
        </div>
        {currentComponents.length > 0 ? (
          <>
            <div className="table-container"><table className="enterprise-table"><thead>
                <tr className="bg-gray-100 text-left text-sm text-gray-600 uppercase tracking-wider">
                  <th className="p-3 font-semibold">Name</th>
                  <th className="p-3 font-semibold">Version</th>
                  <th className="p-3 font-semibold">Type</th>
                  <th className="p-3 font-semibold">OS</th>
                  <th className="p-3 font-semibold">CVE Check Needed</th>
                  <th className="p-3 font-semibold">Update Available</th>
                  <th className="p-3 font-semibold">Last Seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {currentComponents.map((comp: any) => (
                  <tr key={comp.db_id} className="hover:bg-gray-50">
                    <td className="p-3 text-sm font-medium text-gray-900">{comp.name}</td>
                    <td className="p-3 text-sm text-gray-600 font-mono">{comp.version}</td>
                    <td className="p-3 text-sm text-gray-600">{comp.type}</td>
                    <td className="p-3 text-sm text-gray-600">{comp.os_info}</td>
                    <td className="p-3">
                      {comp.needs_cve_check ? 
                        <span className="px-2 py-1 text-xs rounded-full bg-red-100 text-red-800">Yes</span> : 
                        <span className="px-2 py-1 text-xs rounded-full bg-gray-100 text-gray-800">No</span>
                      }
                    </td>
                    <td className="p-3 text-sm text-gray-600">{comp.needs_update_check ? 'Yes' : 'No'}</td>
                    <td className="p-3 text-sm text-gray-500">{new Date(comp.last_seen).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table></div>
            {totalPages > 1 && (
              <div className="p-4 border-t flex justify-between items-center bg-gray-50">
                <span className="text-sm text-gray-500">Page {currentPage} of {totalPages}</span>
                <div className="space-x-2">
                  <Button disabled={currentPage === 1} onClick={() => setCurrentPage(p => p - 1)} className="px-3 py-1 border rounded bg-white text-gray-700 hover:bg-gray-50 disabled:opacity-50">Previous</Button>
                  <Button disabled={currentPage === totalPages} onClick={() => setCurrentPage(p => p + 1)} className="px-3 py-1 border rounded bg-white text-gray-700 hover:bg-gray-50 disabled:opacity-50">Next</Button>
                </div>
              </div>
            )}
          </>
        ) : (
          <div className="p-8 text-center text-gray-500 flex flex-col items-center">
            <Package className="w-12 h-12 mb-3 text-gray-300" />
            <p>No software components found matching your search.</p>
          </div>
        )}
      </Card>
    </div>
  );
}
