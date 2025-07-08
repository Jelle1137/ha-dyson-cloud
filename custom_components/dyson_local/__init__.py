"""Support for Dyson devices."""

import asyncio
from datetime import timedelta
from functools import partial
import logging
from typing import List, Optional

from .vendor.libdyson import (
    Dyson360Eye,
    Dyson360Heurist,
    Dyson360VisNav,
    DysonPureHotCool,
    DysonPureHotCoolLink,
    DysonPurifierHumidifyCool,
    MessageType,
    get_device,
)
from .vendor.libdyson.const import DEVICE_TYPE_360_EYE, DEVICE_TYPE_360_HEURIST, DEVICE_TYPE_360_VIS_NAV
from .vendor.libdyson.cloud import (
    DysonAccountCN,
    DysonAccount,
)
from .vendor.libdyson.discovery import DysonDiscovery
from .vendor.libdyson.dyson_device import DysonDevice
from .vendor.libdyson.exceptions import (
    DysonException,
    DysonNetworkError,
    DysonLoginFailure,
)

from homeassistant.components.zeroconf import async_get_instance
from homeassistant.config_entries import ConfigEntry, SOURCE_DISCOVERY
from homeassistant.const import CONF_HOST, EVENT_HOMEASSISTANT_STOP
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    CONF_CREDENTIAL,
    CONF_DEVICE_TYPE,
    CONF_SERIAL,
    CONF_IOT_DETAILS,
    DATA_COORDINATORS,
    DATA_DEVICES,
    DATA_DISCOVERY,
    DOMAIN,
)

from .cloud.const import (
    CONF_REGION,
    CONF_AUTH,
    DATA_ACCOUNT,
    DATA_DEVICES,
)

_LOGGER = logging.getLogger(__name__)

ENVIRONMENTAL_DATA_UPDATE_INTERVAL = timedelta(seconds=30)

PLATFORMS = ["camera"]


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up Dyson integration."""
    hass.data[DOMAIN] = {
        DATA_DEVICES: {},
        DATA_COORDINATORS: {},
        DATA_DISCOVERY: None,
    }
    return True


async def async_setup_account(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up a MyDyson Account."""
    if entry.data[CONF_REGION] == "CN":
        account = DysonAccountCN(entry.data[CONF_AUTH])
    else:
        account = DysonAccount(entry.data[CONF_AUTH])
    try:
        devices = await hass.async_add_executor_job(account.devices)

        for index, device in enumerate(devices):
            try:
                iot_detail = await hass.async_add_executor_job(
                    account.get_iot_details, device.serial
                )
                _LOGGER.debug("IoT details for device %s: %s", device.serial, iot_detail)

                devices[index] = device.with_iot_details({
                    "client_id": iot_detail["IoTCredentials"]["ClientId"],
                    "endpoint": iot_detail["Endpoint"],
                    "token_value": iot_detail["IoTCredentials"]["TokenValue"],
                    "token_signature": iot_detail["IoTCredentials"]["TokenSignature"],
                })
            except DysonNetworkError as err:
                _LOGGER.error("Failed to fetch IoT details for device %s: %s", device.serial, err)

    except DysonNetworkError as err:
        _LOGGER.error("Cannot connect to Dyson cloud service: %s", err)
        raise ConfigEntryNotReady

    for device in devices:
        _LOGGER.debug("Device to initialize config flow: %s (%s)", device, type(device))
        hass.async_create_task(
            hass.config_entries.flow.async_init(
                DOMAIN,
                context={"source": SOURCE_DISCOVERY},
                data=device,
            )
        )
        _LOGGER.debug("Flow created for device: %s", device.serial)

    hass.data[DOMAIN][entry.entry_id] = {
        DATA_ACCOUNT: account,
        DATA_DEVICES: devices,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Dyson from a config entry."""
    _LOGGER.debug("Starting setup for Dyson entry: %s", entry)

    # Determine if this is a cloud account setup    
    if CONF_REGION in entry.data:
        _LOGGER.debug("Region detected in entry data. Setting up account...") 
        return await async_setup_account(hass, entry)

    # Create device instance
    _LOGGER.debug(
        "Creating device instance for serial: %s, type: %s",
        entry.data[CONF_SERIAL],
        entry.data[CONF_DEVICE_TYPE],
    )

    device = get_device(
        entry.data[CONF_SERIAL],
        entry.data[CONF_CREDENTIAL],
        entry.data[CONF_DEVICE_TYPE],
    )

    # Check if device is a 360 model (vacuum robot)
    device_type = entry.data[CONF_DEVICE_TYPE]
    _LOGGER.info("Device type from config: %s (type: %s)", device_type, type(device_type))
    _LOGGER.info("Checking against 360 models: %s", [DEVICE_TYPE_360_EYE, DEVICE_TYPE_360_HEURIST, DEVICE_TYPE_360_VIS_NAV])
    is_360_model = device_type in [DEVICE_TYPE_360_EYE, DEVICE_TYPE_360_HEURIST, DEVICE_TYPE_360_VIS_NAV]
    _LOGGER.info("Is 360 model: %s", is_360_model)
    
    if is_360_model:
        _LOGGER.info("=== SETTING UP 360 MODEL ===")
        _LOGGER.info("Device is a 360 model: %s", type(device).__name__)
        _LOGGER.info("Device serial: %s", device.serial)
        _LOGGER.info("Entry data keys: %s", list(entry.data.keys()))
        coordinator = None
        
        # 360 models always use IoT connection, never local discovery
        iot_info = entry.data.get(CONF_IOT_DETAILS)
        _LOGGER.info("IoT details present: %s", iot_info is not None)
        if iot_info:
            _LOGGER.info("IoT details found for 360 model %s. Attempting IoT connection.", device.serial)
            _LOGGER.info("IoT endpoint: %s", iot_info.get("endpoint"))
            _LOGGER.info("IoT client_id: %s", iot_info.get("client_id"))
            _LOGGER.info("IoT token_value length: %d", len(iot_info.get("token_value", "")))
            _LOGGER.info("IoT token_signature length: %d", len(iot_info.get("token_signature", "")))
            try:
                # Use the new IoT connection method in a thread executor to avoid blocking
                loop = asyncio.get_event_loop()
                _LOGGER.info("About to call connect_iot() in thread executor...")
                await loop.run_in_executor(
                    None,
                    device.connect_iot,
                    iot_info["endpoint"],
                    iot_info["client_id"],
                    iot_info["token_value"],
                    iot_info["token_signature"]
                )
                _LOGGER.info("Successfully connected to 360 model %s via IoT", device.serial)
                
                # Store device and coordinator in hass data
                hass.data[DOMAIN][DATA_DEVICES][entry.entry_id] = device
                hass.data[DOMAIN][DATA_COORDINATORS][entry.entry_id] = coordinator
                
                # Forward entry setups
                await hass.config_entries.async_forward_entry_setups(entry, _async_get_platforms(device))
                
                _LOGGER.info("Setup complete for 360 model %s.", device.serial)
                return True
                
            except DysonException as err:
                _LOGGER.error("Failed to connect to 360 model %s via IoT: %s", device.serial, err)
                _LOGGER.error("Exception type: %s", type(err).__name__)
                _LOGGER.warning("IoT connection failed for 360 model, but this is expected for some devices")
                
                # For now, continue with setup even if IoT connection fails
                # Store device and coordinator in hass data
                hass.data[DOMAIN][DATA_DEVICES][entry.entry_id] = device
                hass.data[DOMAIN][DATA_COORDINATORS][entry.entry_id] = coordinator
                
                # Forward entry setups
                await hass.config_entries.async_forward_entry_setups(entry, _async_get_platforms(device))
                
                _LOGGER.info("Setup complete for 360 model %s (without active connection).", device.serial)
                return True
            except Exception as err:
                _LOGGER.error("Unexpected error during IoT connection for %s: %s", device.serial, err)
                _LOGGER.error("Exception type: %s", type(err).__name__)
                import traceback
                _LOGGER.error("Full traceback: %s", traceback.format_exc())
                
                # For now, continue with setup even if IoT connection fails
                # Store device and coordinator in hass data
                hass.data[DOMAIN][DATA_DEVICES][entry.entry_id] = device
                hass.data[DOMAIN][DATA_COORDINATORS][entry.entry_id] = coordinator
                
                # Forward entry setups
                await hass.config_entries.async_forward_entry_setups(entry, _async_get_platforms(device))
                
                _LOGGER.info("Setup complete for 360 model %s (without active connection).", device.serial)
                return True
        else:
            _LOGGER.error("No IoT details found for 360 model %s", device.serial)
            _LOGGER.error("Available entry data: %s", entry.data)
            raise ConfigEntryNotReady("360 model requires IoT details")
    else:
        # Set up data update coordinator
        _LOGGER.debug("Device is not a 360 model. Setting up data update coordinator.")

        # Set up coordinator
        async def async_update_data():
            """Poll environmental data from the device."""
            try:
                _LOGGER.debug("Requesting environmental data from device.")
                await hass.async_add_executor_job(device.request_environmental_data)
            except DysonException as err:
                _LOGGER.error(
                    "Failed to request environmental data from device %s: %s",
                    device.serial,
                    err,
                )
                raise UpdateFailed("Failed to request environmental data") from err

        coordinator = DataUpdateCoordinator(
            hass,
            _LOGGER,
            name="environmental",
            update_method=async_update_data,
            update_interval=ENVIRONMENTAL_DATA_UPDATE_INTERVAL,
        )
        _LOGGER.debug("Data update coordinator created.")

        def setup_entry(host: str, is_discovery: bool = True) -> bool:
            """Connect to the device."""
            _LOGGER.warning("Attempting to connect to device at host: %s", host)
            try:
                device.connect(host)
                _LOGGER.info("Successfully connected to device %s at %s", device.serial, host)
            except DysonException as conn_err:
                if is_discovery:
                    _LOGGER.error(
                        "Failed to connect to device %s at %s. Error: %s",
                        device.serial,
                        host,
                        conn_err,
                    )
                    return
                _LOGGER.error(
                    "Critical connection error for device %s: %s. Raising ConfigEntryNotReady.",
                    device.serial,
                    conn_err,
                )
                raise ConfigEntryNotReady

            # Store device and coordinator in hass data
            _LOGGER.debug("Storing device and coordinator in hass data.")
            hass.data[DOMAIN][DATA_DEVICES][entry.entry_id] = device
            hass.data[DOMAIN][DATA_COORDINATORS][entry.entry_id] = coordinator

            # Forward entry setups
            _LOGGER.debug("Forwarding entry setups for platforms.")
            asyncio.run_coroutine_threadsafe(
                hass.config_entries.async_forward_entry_setups(entry, _async_get_platforms(device)), hass.loop
            ).result()

        host = entry.data.get(CONF_HOST)
        if host:
            _LOGGER.debug("Host provided in entry data: %s. Attempting direct connection.", host)
            await hass.async_add_executor_job(
                partial(setup_entry, host, is_discovery=False)
            )
        else:
            _LOGGER.debug("No host in entry data. Attempting discovery.")
            discovery = hass.data[DOMAIN].get(DATA_DISCOVERY)
            if discovery is None:
                _LOGGER.debug("No existing discovery instance. Starting new discovery.")
                discovery = DysonDiscovery()
                hass.data[DOMAIN][DATA_DISCOVERY] = discovery
                discovery.start_discovery(await async_get_instance(hass))

                def stop_discovery(_):
                    _LOGGER.debug("Stopping Dyson discovery.")
                    discovery.stop_discovery()

                hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, stop_discovery)

            try:
                _LOGGER.debug("Registering device for discovery.")
                await hass.async_add_executor_job(
                    discovery.register_device, device, setup_entry
                )
            except DysonException as discovery_err:
                _LOGGER.warning(
                    "Discovery failed for device %s (%s). Error: %s",
                    device.serial,
                    device.device_type,
                    discovery_err,
                )

                iot_info = entry.data.get(CONF_IOT_DETAILS)
                if iot_info:
                    _LOGGER.debug(
                        "IoT details found for device %s. Attempting remote MQTT connection.",
                        device.serial,
                    )
                    try:
                        # Use the new IoT connection method in a thread executor to avoid blocking
                        loop = asyncio.get_event_loop()
                        await loop.run_in_executor(
                            None,
                            device.connect_iot,
                            iot_info["endpoint"],
                            iot_info["client_id"],
                            iot_info["token_value"],
                            iot_info["token_signature"]
                        )
                        _LOGGER.info("Successfully connected to device %s via IoT", device.serial)
                        
                        # Store device and coordinator in hass data
                        _LOGGER.debug("Storing device and coordinator in hass data.")
                        hass.data[DOMAIN][DATA_DEVICES][entry.entry_id] = device
                        hass.data[DOMAIN][DATA_COORDINATORS][entry.entry_id] = coordinator

                        # Forward entry setups
                        _LOGGER.debug("Forwarding entry setups for platforms.")
                        await hass.config_entries.async_forward_entry_setups(entry, _async_get_platforms(device))
                        
                    except DysonException as remote_err:
                        _LOGGER.error(
                            "IoT connection failed for device %s (%s). Error: %s",
                            device.serial,
                            device.device_type,
                            remote_err,
                        )
                        raise ConfigEntryNotReady("All connection methods failed")
                else:
                    _LOGGER.error(
                        "No IoT details available for device %s. Cannot connect remotely.",
                        device.serial,
                    )
                    raise ConfigEntryNotReady("No connection method available")

    _LOGGER.debug("Setup entry complete for device %s.", device.serial)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload Dyson local."""
    device: DysonDevice = hass.data[DOMAIN][DATA_DEVICES][entry.entry_id]

    unload_ok = await hass.config_entries.async_unload_platforms(entry, _async_get_platforms(device))

    if unload_ok:
        hass.data[DOMAIN][DATA_DEVICES].pop(entry.entry_id)
        hass.data[DOMAIN][DATA_COORDINATORS].pop(entry.entry_id)
        await hass.async_add_executor_job(device.disconnect)
        # TODO: stop discovery
    return unload_ok


@callback
def _async_get_platforms(device: DysonDevice) -> List[str]:
    if (isinstance(device, Dyson360Eye)
            or isinstance(device, Dyson360Heurist)
            or isinstance(device, Dyson360VisNav)):
        return ["binary_sensor", "sensor", "vacuum"]
    platforms = ["fan", "select", "sensor", "switch"]
    if isinstance(device, DysonPureHotCool):
        platforms.append("climate")
    if isinstance(device, DysonPureHotCoolLink):
        platforms.extend(["binary_sensor", "climate"])
    if isinstance(device, DysonPurifierHumidifyCool):
        platforms.append("humidifier")
    if hasattr(device, "filter_life") or hasattr(device, "carbon_filter_life") or hasattr(device, "hepa_filter_life"):
        platforms.append("button")
    return platforms


class DysonEntity(Entity):
    """Dyson entity base class."""

    _MESSAGE_TYPE = MessageType.STATE

    def __init__(self, device: DysonDevice, name: str):
        """Initialize the entity."""
        self._device = device
        self._name = name

    async def async_added_to_hass(self) -> None:
        """Call when entity is added to hass."""
        self._device.add_message_listener(self._on_message)

    def _on_message(self, message_type: MessageType) -> None:
        if self._MESSAGE_TYPE is None or message_type == self._MESSAGE_TYPE:
            self.schedule_update_ha_state()

    @property
    def should_poll(self) -> bool:
        """No polling needed."""
        return False

    @property
    def name(self) -> str:
        """Return the name of the entity."""
        if self.sub_name is None:
            return self._name
        return f"{self._name} {self.sub_name}"

    @property
    def sub_name(self) -> Optional[str]:
        """Return sub name of the entity."""
        return None

    @property
    def unique_id(self) -> str:
        """Return the entity unique id."""
        if self.sub_unique_id is None:
            return self._device.serial
        return f"{self._device.serial}-{self.sub_unique_id}"

    @property
    def sub_unique_id(self) -> str:
        """Return the entity sub unique id."""
        return None

    @property
    def device_info(self) -> dict:
        """Return device info of the entity."""
        return {
            "identifiers": {(DOMAIN, self._device.serial)},
            "name": self._name,
            "manufacturer": "Dyson",
            "model": self._device.device_type,
        }
