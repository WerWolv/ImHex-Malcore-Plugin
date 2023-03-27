#include <hex/plugin.hpp>

#include <hex/api/content_registry.hpp>
#include <hex/helpers/logger.hpp>
#include <helpers/malcore_api.hpp>

#include <hex/ui/view.hpp>


IMHEX_PLUGIN_SETUP("Malcore", "WerWolv / Internet 2.0", "Plugin to integrate with Malcore services") {
    mal::hlp::MalcoreApi::setApiKey("00714944e8c63728edbbd54b845b4647c62819b8");

    hex::ContentRegistry::Interface::addMenuItem({ "hex.builtin.menu.help", "Upload to Malcore" }, 10000, hex::Shortcut::None, []{
        auto selection = hex::ImHexApi::HexEditor::getSelection();
        auto uuid = mal::hlp::MalcoreApi::uploadProviderData(selection->getProvider(), selection->getRegion()).get();
        if (!uuid.has_value())
            hex::View::showErrorPopup("Failed to upload data to Malcore");
        else {
            auto data = mal::hlp::MalcoreApi::getAnalysisStatus(uuid.value()).get();
            wolv::io::File file("output.json", wolv::io::File::Mode::Create);
            file.writeString(data->dump(4));
        }
    }, []{
        return hex::ImHexApi::HexEditor::isSelectionValid();
    });
}


