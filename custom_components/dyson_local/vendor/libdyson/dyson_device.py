"""Dyson device."""
from abc import abstractmethod
import json
import logging
import ssl
import threading
from typing import Any, Optional, List, Dict, Union

import paho.mqtt.client as mqtt

from .const import (
    ENVIRONMENTAL_FAIL,
    ENVIRONMENTAL_INIT,
    ENVIRONMENTAL_OFF,
    MessageType,
)
from .exceptions import (
    DysonConnectionRefused,
    DysonConnectTimeout,
    DysonInvalidCredential,
    DysonNotConnected, DysonNoEnvironmentalData,
)
from .utils import mqtt_time

_LOGGER = logging.getLogger(__name__)

TIMEOUT = 10


class DysonDevice:
    """Base class for dyson devices."""

    def __init__(self, serial: str, credential: str):
        """Initialize the device."""
        self._serial = serial
        self._credential = credential
        self._mqtt_client = None
        self._connected = threading.Event()
        self._disconnected = threading.Event()
        self._status = None
        self._status_data_available = threading.Event()
        self._callbacks = []

    @property
    def serial(self) -> str:
        """Return the serial number of the device."""
        return self._serial

    @property
    def is_connected(self) -> bool:
        """Whether MQTT connection is active."""
        return self._connected.is_set()

    @property
    @abstractmethod
    def device_type(self) -> str:
        """Device type."""

    @property
    @abstractmethod
    def _status_topic(self) -> str:
        """MQTT status topic."""

    @property
    def _command_topic(self) -> str:
        """MQTT command topic."""
        return f"{self.device_type}/{self._serial}/command"

    def _request_first_data(self) -> bool:
        """Request and wait for first data."""
        _LOGGER.info("Requesting first data from device %s", self._serial)
        _LOGGER.debug("Clearing status_data_available event")
        self._status_data_available.clear()
        
        _LOGGER.debug("Sending request current status...")
        self.request_current_status()
        
        _LOGGER.info("Waiting for first data (timeout: %d seconds)...", TIMEOUT)
        result = self._status_data_available.wait(timeout=TIMEOUT)
        
        if result:
            _LOGGER.info("Successfully received first data from device %s", self._serial)
        else:
            _LOGGER.error("Timeout waiting for first data from device %s", self._serial)
            
        return result

    def connect(self, host: str) -> None:
        """Connect to the device MQTT broker."""
        self._disconnected.clear()
        self._mqtt_client = mqtt.Client(protocol=mqtt.MQTTv31)
        self._mqtt_client.username_pw_set(self._serial, self._credential)
        error = None

        def _on_connect(client: mqtt.Client, userdata: Any, flags, rc):
            _LOGGER.debug("Connected with result code %d", rc)
            nonlocal error
            if rc == mqtt.CONNACK_REFUSED_BAD_USERNAME_PASSWORD:
                error = DysonInvalidCredential
            elif rc != mqtt.CONNACK_ACCEPTED:
                error = DysonConnectionRefused
            else:
                client.subscribe(self._status_topic)
            self._connected.set()

        def _on_disconnect(client, userdata, rc):
            _LOGGER.debug(f"Disconnected with result code {str(rc)}")

        self._disconnected.set()

        self._mqtt_client.on_connect = _on_connect
        self._mqtt_client.on_disconnect = _on_disconnect
        self._mqtt_client.on_message = self._on_message
        self._mqtt_client.connect_async(host)
        self._mqtt_client.loop_start()
        if self._connected.wait(timeout=TIMEOUT):
            if error is not None:
                self.disconnect()
                raise error

            _LOGGER.info("Connected to device %s", self._serial)
            if self._request_first_data():
                self._mqtt_client.on_connect = self._on_connect
                self._mqtt_client.on_disconnect = self._on_disconnect
                return

        # Close connection if timeout or connected but failed to get data
        self.disconnect()

        raise DysonConnectTimeout

    def connect_iot(self, endpoint: str, client_id: str, token_value: str, token_signature: str) -> None:
        """Connect to the device via IoT/cloud MQTT broker with custom authentication."""
        _LOGGER.info("=== STARTING IOT CONNECTION DEBUG ===")
        _LOGGER.info("Endpoint: %s", endpoint)
        _LOGGER.info("Client ID: %s", client_id)
        _LOGGER.info("Token Value (first 10 chars): %s...", token_value[:10] if token_value else "None")
        _LOGGER.info("Token Signature (first 10 chars): %s...", token_signature[:10] if token_signature else "None")
        _LOGGER.info("Device Serial: %s", self._serial)
        _LOGGER.info("Status Topic: %s", self._status_topic)
        _LOGGER.info("Command Topic: %s", self._command_topic)
        
        self._disconnected.clear()
        
        # Try different MQTT protocol versions
        protocols_to_try = [
            (mqtt.MQTTv311, "MQTTv3.1.1"),
            (mqtt.MQTTv31, "MQTTv3.1"),
            (mqtt.MQTTv5, "MQTTv5") if hasattr(mqtt, 'MQTTv5') else None
        ]
        protocols_to_try = [p for p in protocols_to_try if p is not None]
        
        for protocol_version, protocol_name in protocols_to_try:
            _LOGGER.info("Trying MQTT protocol: %s", protocol_name)
            
            try:
                self._mqtt_client = mqtt.Client(client_id=client_id, protocol=protocol_version)
                _LOGGER.debug("Created MQTT client with protocol %s", protocol_name)
                break
            except Exception as e:
                _LOGGER.warning("Failed to create MQTT client with %s: %s", protocol_name, e)
                continue
        else:
            _LOGGER.error("Failed to create MQTT client with any protocol")
            raise DysonConnectionRefused("Could not create MQTT client")
        
        # Set up TLS for secure connection
        try:
            context = ssl.create_default_context()
            # AWS IoT specific TLS configuration
            context.check_hostname = True  # Re-enable hostname checking for AWS IoT
            context.verify_mode = ssl.CERT_REQUIRED  # Require server certificate validation
            
            # Set minimum TLS version (AWS IoT requires TLS 1.2+)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            
            # Set ciphers to match AWS IoT requirements
            context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            
            self._mqtt_client.tls_set_context(context)
            _LOGGER.debug("TLS context set successfully with AWS IoT configuration")
        except Exception as e:
            _LOGGER.error("Failed to set TLS context: %s", e)
            _LOGGER.info("Trying fallback TLS configuration...")
            try:
                # Fallback to basic TLS
                context = ssl.create_default_context()
                context.check_hostname = False
                self._mqtt_client.tls_set_context(context)
                _LOGGER.debug("Fallback TLS context set successfully")
            except Exception as e2:
                _LOGGER.error("Fallback TLS setup also failed: %s", e2)
                raise DysonConnectionRefused(f"TLS setup failed: {e}, fallback failed: {e2}")
        
        # Set up authentication - try different methods
        try:
            # For AWS IoT Custom Authorizer, the authentication might need to be in a specific format
            # Let's try different combinations based on common patterns
            
            # Method 1: Standard approach - client_id as username, token_value as password
            _LOGGER.info("Setting up standard authentication (client_id as username)...")
            self._mqtt_client.username_pw_set(client_id, token_value)
            _LOGGER.debug("Standard auth set: username=%s, password_len=%d", client_id, len(token_value))
            
        except Exception as e:
            _LOGGER.error("Failed to set authentication: %s", e)
            raise DysonConnectionRefused(f"Auth setup failed: {e}")
        
        # Store alternative auth function for retry
        def try_alternative_auth():
            _LOGGER.info("Trying alternative authentication methods...")
            
            # Method 2: token_signature as username, token_value as password
            try:
                _LOGGER.info("Trying token_signature as username...")
                self._mqtt_client.username_pw_set(token_signature, token_value)
                _LOGGER.debug("Alt auth 1 set: username=%s..., password_len=%d", token_signature[:10], len(token_value))
                return True
            except Exception as e:
                _LOGGER.error("Alt auth 1 failed: %s", e)
            
            # Method 3: Some IoT systems use a combined format
            try:
                _LOGGER.info("Trying combined token format...")
                combined_token = f"{token_value}:{token_signature}"
                self._mqtt_client.username_pw_set(client_id, combined_token)
                _LOGGER.debug("Alt auth 2 set: username=%s, combined_token_len=%d", client_id, len(combined_token))
                return True
            except Exception as e:
                _LOGGER.error("Alt auth 2 failed: %s", e)
            
            # Method 4: Try empty username with token as password
            try:
                _LOGGER.info("Trying empty username with token as password...")
                self._mqtt_client.username_pw_set("", token_value)
                _LOGGER.debug("Alt auth 3 set: empty username, token_len=%d", len(token_value))
                return True
            except Exception as e:
                _LOGGER.error("Alt auth 3 failed: %s", e)
            
            return False
        
        # Track connection state
        error = None
        connection_result = None
        connection_attempted = False
        auth_retry_attempted = False
        
        def _on_connect(client: mqtt.Client, userdata: Any, flags, rc):
            nonlocal error, connection_result, auth_retry_attempted
            connection_result = rc
            _LOGGER.info("IoT MQTT Connection callback triggered with result code: %d", rc)
            _LOGGER.info("Connection flags: %s", flags)
            
            # Log detailed connection result
            result_meanings = {
                0: "Connection Accepted",
                1: "Incorrect protocol version",
                2: "Invalid client identifier",
                3: "Server unavailable",
                4: "Bad username or password",
                5: "Not authorized"
            }
            result_meaning = result_meanings.get(rc, f"Unknown result code: {rc}")
            _LOGGER.info("Connection result meaning: %s", result_meaning)
            
            # If authentication failed, try alternative method
            if rc == mqtt.CONNACK_REFUSED_BAD_USERNAME_PASSWORD and not auth_retry_attempted:
                _LOGGER.warning("Authentication failed, trying alternative authentication...")
                auth_retry_attempted = True
                
                # Disconnect and retry with alternative auth
                try:
                    client.disconnect()
                    if try_alternative_auth():
                        _LOGGER.info("Retrying connection with alternative authentication...")
                        client.connect_async(endpoint, 8883, 60)
                        return
                except Exception as e:
                    _LOGGER.error("Failed to retry with alternative auth: %s", e)
                
                error = DysonInvalidCredential
            elif rc == mqtt.CONNACK_REFUSED_BAD_USERNAME_PASSWORD:
                _LOGGER.error("IoT connection refused: Bad username/password (after retry)")
                _LOGGER.error("Username used: %s", client_id)
                _LOGGER.error("Password length: %d", len(token_value) if token_value else 0)
                error = DysonInvalidCredential
            elif rc == mqtt.CONNACK_REFUSED_IDENTIFIER_REJECTED:
                _LOGGER.error("IoT connection refused: Client identifier rejected")
                _LOGGER.error("Client ID used: %s", client_id)
                error = DysonConnectionRefused
            elif rc == mqtt.CONNACK_REFUSED_SERVER_UNAVAILABLE:
                _LOGGER.error("IoT connection refused: Server unavailable")
                error = DysonConnectionRefused
            elif rc == mqtt.CONNACK_REFUSED_NOT_AUTHORIZED:
                _LOGGER.error("IoT connection refused: Not authorized")
                error = DysonInvalidCredential
            elif rc != mqtt.CONNACK_ACCEPTED:
                _LOGGER.error("IoT connection refused with code: %d (%s)", rc, result_meaning)
                error = DysonConnectionRefused
            else:
                _LOGGER.info("IoT connection successful! Subscribing to topic: %s", self._status_topic)
                _LOGGER.info("Command topic will be: %s", self._command_topic)
                _LOGGER.info("Device type: %s", getattr(self, 'device_type', 'Unknown'))
                try:
                    result = client.subscribe(self._status_topic)
                    _LOGGER.info("Subscribe result: %s", result)
                except Exception as e:
                    _LOGGER.error("Failed to subscribe to topic %s: %s", self._status_topic, e)
            
            self._connected.set()

        def _on_disconnect(client, userdata, rc):
            _LOGGER.warning("IoT MQTT Disconnected with result code: %s", rc)
            self._connected.clear()
            self._disconnected.set()
            
        def _on_log(client, userdata, level, buf):
            _LOGGER.debug("MQTT Log (level %s): %s", level, buf)
            
        def _on_publish(client, userdata, mid):
            _LOGGER.debug("MQTT message published with message ID: %s", mid)
            
        def _on_subscribe(client, userdata, mid, granted_qos):
            _LOGGER.info("MQTT subscription confirmed - Message ID: %s, QoS: %s", mid, granted_qos)

        # Set up all MQTT callbacks
        self._mqtt_client.on_connect = _on_connect
        self._mqtt_client.on_disconnect = _on_disconnect
        self._mqtt_client.on_message = self._on_message
        self._mqtt_client.on_log = _on_log
        self._mqtt_client.on_publish = _on_publish
        self._mqtt_client.on_subscribe = _on_subscribe
        
        self._disconnected.set()
        
        # Connect to IoT endpoint
        _LOGGER.info("Attempting to connect to %s:8883", endpoint)
        
        # First, let's test if we can reach the endpoint
        _LOGGER.info("Testing network connectivity to %s:8883...", endpoint)
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            result = sock.connect_ex((endpoint, 8883))
            sock.close()
            if result == 0:
                _LOGGER.info("Network connectivity test: SUCCESS - can reach %s:8883", endpoint)
            else:
                _LOGGER.warning("Network connectivity test: FAILED - cannot reach %s:8883 (error: %d)", endpoint, result)
        except Exception as e:
            _LOGGER.warning("Network connectivity test failed: %s", e)
        
        try:
            self._mqtt_client.connect_async(endpoint, 8883, 60)  # Increased keepalive
            _LOGGER.debug("connect_async() called successfully")
        except Exception as e:
            _LOGGER.error("Failed to call connect_async(): %s", e)
            raise DysonConnectionRefused(f"Connection attempt failed: {e}")
        
        try:
            self._mqtt_client.loop_start()
            _LOGGER.debug("MQTT loop started")
        except Exception as e:
            _LOGGER.error("Failed to start MQTT loop: %s", e)
            raise DysonConnectionRefused(f"MQTT loop start failed: {e}")
        
        # Wait for connection with longer timeout
        extended_timeout = 30  # Increased from 10 to 30 seconds
        _LOGGER.info("Waiting for connection (timeout: %d seconds)...", extended_timeout)
        
        if self._connected.wait(timeout=extended_timeout):
            if error is not None:
                _LOGGER.error("IoT connection failed with error: %s, result code: %s", error, connection_result)
                self.disconnect()
                raise error

            _LOGGER.info("Successfully connected to device %s via IoT!", self._serial)
            
            # Request initial data
            _LOGGER.info("Requesting initial device data...")
            try:
                if self._request_first_data():
                    _LOGGER.info("Successfully received initial data from device %s", self._serial)
                    # Set normal callbacks
                    self._mqtt_client.on_connect = self._on_connect
                    self._mqtt_client.on_disconnect = self._on_disconnect
                    return
                else:
                    _LOGGER.error("Failed to get initial data from IoT device %s within timeout", self._serial)
            except Exception as e:
                _LOGGER.error("Exception while requesting initial data: %s", e)

        else:
            _LOGGER.error("IoT connection timed out after %d seconds", extended_timeout)

        # Close connection if timeout or connected but failed to get data
        _LOGGER.error("Disconnecting due to connection failure")
        self.disconnect()
        raise DysonConnectTimeout

    def disconnect(self) -> None:
        """Disconnect from the device."""
        self._connected.clear()
        self._mqtt_client.disconnect()
        if not self._disconnected.wait(timeout=TIMEOUT):
            _LOGGER.warning("Disconnect timed out")
        self._mqtt_client.loop_stop()
        self._mqtt_client = None

    def add_message_listener(self, callback) -> None:
        """Add a callback to receive update notification."""
        self._callbacks.append(callback)

    def remove_message_listener(self, callback) -> None:
        """Remove an existed callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def _on_connect(self, client: mqtt.Client, userdata: Any, flags, rc):
        _LOGGER.debug("Connected with result code %d", rc)
        self._disconnected.clear()
        self._connected.set()
        client.subscribe(self._status_topic)
        for callback in self._callbacks:
            callback(MessageType.STATE)

    def _on_disconnect(self, client, userdata, rc):
        _LOGGER.debug(f"Disconnected with result code {str(rc)}")
        self._connected.clear()
        self._disconnected.set()
        for callback in self._callbacks:
            callback(MessageType.STATE)

    def _on_message(self, client, userdata: Any, msg: mqtt.MQTTMessage):
        _LOGGER.info("IoT MQTT message received on topic: %s", msg.topic)
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
            _LOGGER.debug("Message payload: %s", payload)
            self._handle_message(payload)
        except Exception as e:
            _LOGGER.error("Error processing MQTT message: %s", e)
            _LOGGER.error("Raw message payload: %s", msg.payload)

    def _handle_message(self, payload: dict) -> None:
        _LOGGER.debug("Handling message with payload: %s", payload)
        msg_type = payload.get("msg", "Unknown")
        
        if msg_type in ["CURRENT-STATE", "STATE-CHANGE"]:
            _LOGGER.info("Processing state message: %s", msg_type)
            _LOGGER.debug("New state: %s", payload)
            self._update_status(payload)
            if not self._status_data_available.is_set():
                _LOGGER.debug("Setting status_data_available event")
                self._status_data_available.set()
            _LOGGER.debug("Calling %d callbacks", len(self._callbacks))
            for callback in self._callbacks:
                callback(MessageType.STATE)
        elif msg_type == "ENVIRONMENTAL-CURRENT-SENSOR-DATA":
            _LOGGER.info("Processing environmental sensor data message")
            # This is environmental data, let's handle it if the device supports it
            if hasattr(self, '_update_environmental_data'):
                self._update_environmental_data(payload)
            else:
                _LOGGER.debug("Device does not support environmental data updates")
        else:
            _LOGGER.warning("Unhandled message type: %s", msg_type)
            _LOGGER.debug("Full unhandled message payload: %s", payload)

    @abstractmethod
    def _update_status(self, payload: dict) -> None:
        """Update the device status."""

    def _send_command(self, command: str, data: Optional[dict] = None) -> None:
        if not self.is_connected:
            raise DysonNotConnected
        if data is None:
            data = {}
        payload = {
            "msg": command,
            "time": mqtt_time(),
        }
        payload.update(data)
        self._mqtt_client.publish(self._command_topic, json.dumps(payload))

    def request_current_status(self) -> None:
        """Request current status."""
        if not self.is_connected:
            _LOGGER.error("Cannot request current status - device not connected")
            raise DysonNotConnected
            
        _LOGGER.debug("Publishing REQUEST-CURRENT-STATE to topic: %s", self._command_topic)
        payload = {
            "msg": "REQUEST-CURRENT-STATE",
            "time": mqtt_time(),
        }
        _LOGGER.debug("Request payload: %s", payload)
        
        try:
            result = self._mqtt_client.publish(self._command_topic, json.dumps(payload))
            _LOGGER.debug("Publish result: %s", result)
        except Exception as e:
            _LOGGER.error("Failed to publish request current status: %s", e)


class DysonFanDevice(DysonDevice):
    """Dyson fan device."""

    def __init__(self, serial: str, credential: str, device_type: str):
        """Initialize the device."""
        super().__init__(serial, credential)
        self._device_type = device_type

        self._environmental_data = {}
        self._environmental_data_available = threading.Event()

    @property
    def device_type(self) -> str:
        """Device type."""
        return self._device_type

    @property
    def _status_topic(self) -> str:
        """MQTT status topic."""
        return f"{self.device_type}/{self._serial}/status/current"

    @property
    def fan_state(self) -> bool:
        """Return if the fan is running."""
        return self._get_field_value(self._status, "fnst") == "FAN"

    @property
    def speed(self) -> Optional[int]:
        """Return fan speed."""
        speed = self._get_field_value(self._status, "fnsp")
        if speed == "AUTO":
            return None
        return int(speed)

    @property
    @abstractmethod
    def is_on(self) -> bool:
        """Return if the device is on."""

    @property
    @abstractmethod
    def auto_mode(self) -> bool:
        """Return auto mode status."""

    @property
    @abstractmethod
    def oscillation(self) -> bool:
        """Return oscillation status."""

    @property
    def night_mode(self) -> bool:
        """Return night mode status."""
        return self._get_field_value(self._status, "nmod") == "ON"

    @property
    def continuous_monitoring(self) -> bool:
        """Return standby monitoring status."""
        return self._get_field_value(self._status, "rhtm") == "ON"

    @property
    def error_code(self) -> str:
        """Return error code."""
        return self._get_field_value(self._status, "ercd")

    @property
    def warning_code(self) -> str:
        """Return warning code."""
        return self._get_field_value(self._status, "wacd")

    @property
    def formaldehyde(self) -> Optional[float]:
        """Return formaldehyde reading."""
        val = self._get_environmental_field_value("hchr", divisor=1000)
        if val is None:
            return None

        return float(val)

    @property
    def humidity(self) -> int:
        """Return humidity in percentage."""
        return self._get_environmental_field_value("hact")

    @property
    def temperature(self) -> int:
        """Return temperature in kelvin."""
        return self._get_environmental_field_value("tact", divisor=10)

    @property
    @abstractmethod
    def volatile_organic_compounds(self) -> int:
        """Return VOCs."""

    @property
    def sleep_timer(self) -> int:
        """Return sleep timer in minutes."""
        return self._get_environmental_field_value("sltm")

    @staticmethod
    def _get_field_value(state: Dict[str, Any], field: str):
        try:
            return  state[field][1] if isinstance(state[field], list) else state[field]
        except:
            return None

    def _get_environmental_field_value(self, field, divisor=1) -> Optional[Union[int, float]]:
        value = self._get_field_value(self._environmental_data, field)
        if value == "OFF" or value == "off":
            return ENVIRONMENTAL_OFF
        if value == "INIT":
            return ENVIRONMENTAL_INIT
        if value == "FAIL":
            return ENVIRONMENTAL_FAIL
        if value == "NONE" or value is None:
            return None
        if divisor == 1:
            return int(value)
        return float(value) / divisor

    def _handle_message(self, payload: dict) -> None:
        super()._handle_message(payload)
        if payload["msg"] == "ENVIRONMENTAL-CURRENT-SENSOR-DATA":
            _LOGGER.debug("New environmental state: %s", payload)
            self._environmental_data = payload["data"]
            if not self._environmental_data_available.is_set():
                self._environmental_data_available.set()
            for callback in self._callbacks:
                callback(MessageType.ENVIRONMENTAL)

    def _update_status(self, payload: dict) -> None:
        self._status = payload["product-state"]

    def _set_configuration(self, **kwargs: dict) -> None:
        if not self.is_connected:
            raise DysonNotConnected
        payload = json.dumps(
            {
                "msg": "STATE-SET",
                "time": mqtt_time(),
                "mode-reason": "LAPP",
                "data": kwargs,
            }
        )
        self._mqtt_client.publish(self._command_topic, payload, 1)

    def _request_first_data(self) -> bool:
        """Request and wait for first data."""
        self.request_current_status()
        self.request_environmental_data()
        status_available = self._status_data_available.wait(timeout=TIMEOUT)
        environmental_available = self._environmental_data_available.wait(
            timeout=TIMEOUT
        )
        return status_available and environmental_available

    def request_environmental_data(self):
        """Request environmental sensor data."""
        if not self.is_connected:
            raise DysonNotConnected
        payload = {
            "msg": "REQUEST-PRODUCT-ENVIRONMENT-CURRENT-SENSOR-DATA",
            "time": mqtt_time(),
        }
        self._mqtt_client.publish(self._command_topic, json.dumps(payload))

    @abstractmethod
    def turn_on(self) -> None:
        """Turn on the device."""

    @abstractmethod
    def turn_off(self) -> None:
        """Turn off the device."""

    def set_speed(self, speed: int) -> None:
        """Set manual speed."""
        if not 1 <= speed <= 10:
            raise ValueError("Invalid speed %s", speed)
        self._set_speed(speed)

    @abstractmethod
    def _set_speed(self, speed: int) -> None:
        """Actually set the speed without range check."""

    @abstractmethod
    def enable_auto_mode(self) -> None:
        """Turn on auto mode."""

    @abstractmethod
    def disable_auto_mode(self) -> None:
        """Turn off auto mode."""

    @abstractmethod
    def enable_oscillation(self) -> None:
        """Turn on oscillation."""

    @abstractmethod
    def disable_oscillation(self) -> None:
        """Turn off oscillation."""

    def enable_night_mode(self) -> None:
        """Turn on auto mode."""
        self._set_configuration(nmod="ON")

    def disable_night_mode(self) -> None:
        """Turn off auto mode."""
        self._set_configuration(nmod="OFF")

    @abstractmethod
    def enable_continuous_monitoring(self) -> None:
        """Turn on continuous monitoring."""

    @abstractmethod
    def disable_continuous_monitoring(self) -> None:
        """Turn off continuous monitoring."""

    def set_sleep_timer(self, duration: int) -> None:
        """Set sleep timer."""
        if not 0 < duration <= 540:
            raise ValueError("Duration must be between 1 and 540")
        self._set_configuration(sltm="%04d" % duration)

    def disable_sleep_timer(self) -> None:
        """Disable sleep timer."""
        self._set_configuration(sltm="OFF")

    def reset_filter(self) -> None:
        """Reset filter life."""
        self._set_configuration(rstf="RSTF")


class DysonHeatingDevice(DysonFanDevice):
    """Dyson heating fan device."""

    @property
    def focus_mode(self) -> bool:
        """Return if fan focus mode is on."""
        return self._get_field_value(self._status, "ffoc") == "ON"

    @property
    def heat_target(self) -> float:
        """Return heat target in kelvin."""
        return int(self._get_field_value(self._status, "hmax")) / 10

    @property
    def heat_mode_is_on(self) -> bool:
        """Return if heat mode is set to on."""
        return self._get_field_value(self._status, "hmod") == "HEAT"

    @property
    def heat_status_is_on(self) -> bool:
        """Return if the device is currently heating."""
        return self._get_field_value(self._status, "hsta") == "HEAT"

    def set_heat_target(self, heat_target: float) -> None:
        """Set heat target in kelvin."""
        if not 274 <= heat_target <= 310:
            raise ValueError("Heat target must be between 274 and 310 kelvin")
        self._set_configuration(
            hmod="HEAT",
            hmax=f"{round(heat_target * 10):04d}",
        )

    def enable_heat_mode(self) -> None:
        """Enable heat mode."""
        self._set_configuration(hmod="HEAT")

    def disable_heat_mode(self) -> None:
        """Disable heat mode."""
        self._set_configuration(hmod="OFF")
