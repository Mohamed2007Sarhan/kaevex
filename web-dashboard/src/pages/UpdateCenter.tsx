import React from 'react';
import { RefreshCw, Package, CheckCircle, AlertCircle, ArrowRight } from 'lucide-react';
import { Card } from '../components/UI/Card';
import { Button } from '../components/UI/Button';
import { api } from '../api/client';

interface UpdateCenterProps {
  liveData: any;
  addToast: any;
}

export default function UpdateCenter({ liveData, addToast }: UpdateCenterProps) {
  const { updateReport } = liveData;

  const handleRunUpdateCheck = async () => {
    try {
      await api.hostguardForceScan();
      addToast('Update check initiated', 'info');
    } catch (err) {
      addToast('Failed to initiate update check', 'error');
    }
  };

  const getBadgeForType = (type: string) => {
    switch (type?.toLowerCase()) {
      case 'security': return <span className="px-2 py-1 text-xs rounded-full bg-red-100 text-red-800 font-medium">Security</span>;
      case 'bugfix': return <span className="px-2 py-1 text-xs rounded-full bg-yellow-100 text-yellow-800 font-medium">Bugfix</span>;
      case 'feature': return <span className="px-2 py-1 text-xs rounded-full bg-blue-100 text-blue-800 font-medium">Feature</span>;
      default: return <span className="px-2 py-1 text-xs rounded-full bg-gray-100 text-gray-800 font-medium">{type}</span>;
    }
  };

  const hasPending = updateReport?.pending && updateReport.pending.length > 0;

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900">Update Center</h1>
        <Button onClick={handleRunUpdateCheck} className="flex items-center space-x-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded">
          <RefreshCw className="w-4 h-4" />
          <span>Run Update Check</span>
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card className="p-6 flex items-center space-x-4 border-l-4 border-green-500">
          <div className="p-3 bg-green-100 rounded-full text-green-600">
            <CheckCircle className="w-8 h-8" />
          </div>
          <div>
            <div className="text-3xl font-bold text-gray-900">{updateReport?.auto_installed || 0}</div>
            <div className="text-sm font-medium text-gray-500">Auto-Installed Updates</div>
          </div>
        </Card>
        <Card className="p-6 flex items-center space-x-4 border-l-4 border-orange-500">
          <div className="p-3 bg-orange-100 rounded-full text-orange-600">
            <AlertCircle className="w-8 h-8" />
          </div>
          <div>
            <div className="text-3xl font-bold text-gray-900">{updateReport?.user_required || 0}</div>
            <div className="text-sm font-medium text-gray-500">User Attention Required</div>
          </div>
        </Card>
      </div>

      <Card className="p-0 overflow-hidden">
        <div className="p-4 border-b bg-gray-50 flex items-center">
          <Package className="w-5 h-5 mr-2 text-gray-600" />
          <h2 className="text-lg font-bold text-gray-900">Pending Updates</h2>
        </div>
        
        {hasPending ? (
          <div className="table-container"><table className="enterprise-table"><thead>
              <tr className="bg-gray-100 text-left text-sm text-gray-600 uppercase tracking-wider">
                <th className="p-3 font-semibold">Component</th>
                <th className="p-3 font-semibold">Type</th>
                <th className="p-3 font-semibold">Version Upgrade</th>
                <th className="p-3 font-semibold">Update Safe</th>
                <th className="p-3 font-semibold">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {updateReport.pending.map((item: any, i: number) => {
                const isUserRequired = item.status?.toLowerCase() === 'user_required' || item.update_safe === false;
                return (
                  <tr key={i} className={`hover:bg-gray-50 ${isUserRequired ? 'border-l-4 border-l-orange-500' : ''}`}>
                    <td className="p-3 text-sm font-medium text-gray-900">{item.component}</td>
                    <td className="p-3">{getBadgeForType(item.type)}</td>
                    <td className="p-3 text-sm">
                      <div className="flex items-center space-x-2">
                        <span className="font-mono text-gray-500">{item.current_version}</span>
                        <ArrowRight className="w-4 h-4 text-gray-400" />
                        <span className="font-mono font-medium text-blue-600">{item.latest_version}</span>
                      </div>
                    </td>
                    <td className="p-3">
                      {item.update_safe ? 
                        <span className="px-2 py-1 text-xs rounded-full bg-green-100 text-green-800">Yes</span> : 
                        <span className="px-2 py-1 text-xs rounded-full bg-red-100 text-red-800">No</span>
                      }
                    </td>
                    <td className="p-3">
                      <span className={`px-2 py-1 text-xs rounded-full ${isUserRequired ? 'bg-orange-100 text-orange-800' : 'bg-gray-100 text-gray-800'}`}>
                        {item.status || 'Pending'}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table></div>
        ) : (
          <div className="p-12 flex flex-col items-center justify-center text-gray-500">
            <CheckCircle className="w-16 h-16 text-green-500 mb-4" />
            <h3 className="text-xl font-medium text-gray-900 mb-1">System is up to date</h3>
            <p>No pending updates found for tracked components.</p>
          </div>
        )}
      </Card>
    </div>
  );
}
