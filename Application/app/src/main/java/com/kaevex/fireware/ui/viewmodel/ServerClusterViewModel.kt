package com.kaevex.fireware.ui.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.kaevex.fireware.data.model.ServerNode
import com.kaevex.fireware.domain.network.DiscoveredHost
import com.kaevex.fireware.domain.repository.ClusterRepository
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class ClusterUiState(
    val servers: List<ServerNode> = emptyList(),
    val activeServer: ServerNode? = null,
    val isBroadcasting: Boolean = false,
    val isScanning: Boolean = false,
    val showAddDialog: Boolean = false,
    val discoveredHosts: List<DiscoveredHost> = emptyList()
)

class ServerClusterViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = ClusterRepository(application)

    private val _uiState = MutableStateFlow(ClusterUiState())
    val uiState: StateFlow<ClusterUiState> = _uiState.asStateFlow()

    private val _userMessage = MutableSharedFlow<String>()
    val userMessage: SharedFlow<String> = _userMessage.asSharedFlow()

    init {
        viewModelScope.launch {
            repository.servers.collect { list ->
                _uiState.value = _uiState.value.copy(servers = list)
            }
        }
        viewModelScope.launch {
            repository.activeServer.collect { node ->
                _uiState.value = _uiState.value.copy(activeServer = node)
            }
        }
        refreshLivePings()
    }

    fun refreshLivePings() {
        viewModelScope.launch {
            repository.refreshAllPings()
        }
    }

    fun startAutoDiscovery() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isScanning = true, discoveredHosts = emptyList())
            _userMessage.emit("Scanning local subnet for Windows Kaevex SOC on port 9009...")
            val foundList = mutableListOf<DiscoveredHost>()
            repository.scanLocalNetworkForHosts { host ->
                foundList.add(host)
                _uiState.value = _uiState.value.copy(discoveredHosts = foundList.toList())
                viewModelScope.launch {
                    _userMessage.emit("Detected Kaevex Host at ${host.ip}:${host.port} (${host.pingMs}ms)")
                }
            }
            _uiState.value = _uiState.value.copy(isScanning = false)
        }
    }

    fun selectServer(server: ServerNode) {
        viewModelScope.launch {
            repository.selectActiveServer(server)
            _userMessage.emit("Switched active SOC command node to ${server.name}")
        }
    }

    fun setShowAddDialog(show: Boolean) {
        _uiState.value = _uiState.value.copy(showAddDialog = show)
    }

    fun addServer(ip: String, port: Int, pin: String, name: String, role: String) {
        viewModelScope.launch {
            val result = repository.pairNewServer(ip, port, pin, name, role)
            result.onSuccess { node ->
                _uiState.value = _uiState.value.copy(showAddDialog = false)
                _userMessage.emit("Successfully paired node ${node.name} (${node.ip})")
            }.onFailure {
                _userMessage.emit("Pairing failed: ${it.message}")
            }
        }
    }

    fun deleteServer(server: ServerNode) {
        viewModelScope.launch {
            repository.deleteServer(server)
            _userMessage.emit("Removed server ${server.name} from cluster profiles")
        }
    }

    fun broadcastLockdownAll() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isBroadcasting = true)
            val result = repository.broadcastAction("lockdown-all")
            _uiState.value = _uiState.value.copy(isBroadcasting = false)
            result.onSuccess {
                _userMessage.emit(it.message)
            }.onFailure {
                _userMessage.emit("Broadcast failed: ${it.message}")
            }
        }
    }

    fun broadcastAuditAll() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isBroadcasting = true)
            val result = repository.broadcastAction("scan-all")
            _uiState.value = _uiState.value.copy(isBroadcasting = false)
            result.onSuccess {
                _userMessage.emit(it.message)
            }.onFailure {
                _userMessage.emit("Audit broadcast failed: ${it.message}")
            }
        }
    }
}
