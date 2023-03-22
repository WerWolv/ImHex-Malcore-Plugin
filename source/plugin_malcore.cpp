#include <hex/plugin.hpp>

#include <hex/api/content_registry.hpp>
#include <hex/helpers/logger.hpp>
#include <helpers/malcore_api.hpp>

#include <hex/ui/view.hpp>


IMHEX_PLUGIN_SETUP("Malcore", "WerWolv / Internet 2.0", "Plugin to integrate with Malcore services") {
    hex::ContentRegistry::Interface::addMenuItem({ "hex.builtin.menu.help", "Upload to Malcore" }, 10000, hex::Shortcut::None, []{

    });
}


