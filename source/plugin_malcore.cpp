#include <hex/plugin.hpp>

#include <hex/api/theme_manager.hpp>

#include <hex/api/content_registry.hpp>
#include <hex/api/task.hpp>
#include <hex/helpers/logger.hpp>
#include <helpers/malcore_api.hpp>

#include <hex/ui/view.hpp>

#include <fonts/codicons_font.h>

#include <hex/api/localization.hpp>
#include <romfs/romfs.hpp>

using namespace hex;

namespace {

    static ImGui::Texture s_bannerTexture;

    class ViewMalcore : public View {
    public:
        ViewMalcore() : View("mal.view.malcore") {

        }

        void drawContent() override {
            if (ImGui::Begin(LangEntry(this->getUnlocalizedName()), &this->getWindowOpenState())) {
                if (ImGui::BeginChild("##scroll", ImVec2(0, 0), false, ImGuiWindowFlags_AlwaysVerticalScrollbar)) {
                    if (this->m_packerInformation.has_value()) {
                        ImGui::Header("mal.view.malcore.packer"_lang, true);

                        const auto &packer = this->m_packerInformation.value();
                        ImGui::TextFormattedWrapped("mal.view.malcore.packer.text"_lang, packer.name, packer.confidence);

                        ImGui::NewLine();
                    }

                    if (this->m_threatScore.has_value()) {
                        ImGui::Header("mal.view.malcore.threat_score"_lang, true);

                        const auto &threatScore = this->m_threatScore.value();

                        auto color = [&threatScore]{
                            ImColor color;
                            color.SetHSV(3 - (threatScore.score / 100.0f) * 3, 0.8F, 0.8F);

                            return color;
                        }();

                        ImGui::PushStyleColor(ImGuiCol_PlotHistogram, u32(color));
                        ImGui::PushItemWidth(-1);
                        const auto text = hex::format("mal.view.malcore.threat_score.text"_lang, threatScore.score);
                        ImGui::ProgressBar(threatScore.score / 100.0f, ImVec2(0, 0), text.c_str());
                        ImGui::PopItemWidth();
                        ImGui::PopStyleColor();

                        ImGui::NewLine();

                        int id = 1;
                        for (const auto &[title, description, discovered] : threatScore.signatures) {
                            ImGui::PushID(id);
                            if (ImGui::CollapsingHeader(title.c_str())) {
                                ImGui::TextFormattedWrapped("{}", description);
                                ImGui::NewLine();
                            }
                            ImGui::PopID();

                            id += 1;
                        }

                        ImGui::NewLine();
                    }

                    if (this->m_dynamicAnalysisResults.has_value()) {
                        ImGui::Header("mal.view.malcore.dynamic_analysis"_lang, true);

                        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
                        const auto &dynamicAnalysisResults = this->m_dynamicAnalysisResults.value();
                        int id = 1;
                        for (const auto &[hash, apis] : dynamicAnalysisResults) {

                            ImGui::PushID(id);
                            if (ImGui::CollapsingHeader(hash.c_str())) {
                                if (ImGui::BeginTable("API", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_RowBg)) {
                                    ImGui::TableSetupColumn("mal.view.malcore.dynamic_analysis.pc"_lang);
                                    ImGui::TableSetupColumn("mal.view.malcore.dynamic_analysis.function"_lang);
                                    ImGui::TableHeadersRow();

                                    for (const auto &api : apis) {
                                        ImGui::TableNextRow();
                                        ImGui::TableNextColumn();
                                        ImGui::TextFormatted("0x{:02X}", api.pcValue);
                                        ImGui::TableNextColumn();

                                        ImGui::TextFormatted("{}(", api.apiName);
                                        ImGui::SameLine(0, 0);
                                        for (u32 i = 0; i < api.arguments.size(); i++) {
                                            char *end = nullptr;
                                            std::strtoll(api.arguments[i].c_str(), &end, 0);

                                            if (end == nullptr || *end != '\0')
                                                ImGui::TextFormattedColored(ImColor(0xFF7070E0), "\"{}\"", api.arguments[i]);
                                            else
                                                ImGui::TextFormattedColored(ImColor(0xFF9BC64D), "{}", api.arguments[i]);

                                            ImGui::SameLine(0, 0);
                                            if (i != api.arguments.size() - 1) {
                                                ImGui::TextFormatted(", ");
                                                ImGui::SameLine(0, 0);
                                            }
                                        }
                                        ImGui::SameLine(0, 0);
                                        ImGui::TextFormatted(")", api.apiName);
                                        if (!api.returnValue.empty()) {
                                            ImGui::SameLine(0, 0);
                                            ImGui::TextFormatted(" -> ");
                                            ImGui::SameLine(0, 0);
                                            ImGui::TextFormattedColored(ImColor(0xFF9BC64D), "{}", api.returnValue);
                                        }
                                    }

                                    ImGui::EndTable();
                                }
                                ImGui::NewLine();
                            }
                            ImGui::PopID();

                            id += 1;
                        }
                        ImGui::PopStyleVar();

                        ImGui::NewLine();
                    }

                    if (this->m_interestingStrings.has_value()) {
                        ImGui::Header("mal.view.malcore.interesting_strings"_lang, true);

                        const auto &interestingStrings = this->m_interestingStrings.value();
                        if (ImGui::BeginTable("##interesting_strings", 1, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, scaled(ImVec2(0, 250)))) {
                            ImGui::TableSetupColumn("##value");

                            for (const auto &string : interestingStrings) {
                                ImGui::TableNextRow();
                                ImGui::TableNextColumn();
                                ImGui::TextFormattedWrapped("{}", string);
                            }

                            ImGui::EndTable();
                        }

                        ImGui::NewLine();
                    }
                }
                ImGui::EndChild();
            }
            ImGui::End();
        }

        void drawAlwaysVisible() override {
            const auto windowWidth = 450_scaled;
            ImGui::SetNextWindowSize(ImVec2(windowWidth, 0), ImGuiCond_Always);
            if (ImGui::BeginPopupModal("mal.malcore.popup.api_key"_lang, nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
                if (!mal::hlp::MalcoreApi::hasApiKey()) {
                    const auto imageSize = scaled(s_bannerTexture.getSize() * 0.35F);

                    ImGui::SetCursorPosX((windowWidth - imageSize.x) / 2.0F);
                    ImGui::Image(s_bannerTexture, imageSize);

                    ImGui::NewLine();

                    ImGui::TextWrapped("mal.malcore.popup.api_key.description"_lang);
                    ImGui::NewLine();
                    ImGui::TextWrapped("mal.malcore.popup.api_key.register"_lang);
                    if (ImGui::Hyperlink("https://malcore.io/register"))
                        hex::openWebpage("https://malcore.io/register");

                    ImGui::NewLine();

                    ImGui::PushItemWidth(windowWidth - ImGui::GetStyle().FramePadding.x * 4.0F);
                    if (ImGui::InputTextIcon("##api_key", ICON_VS_SYMBOL_KEY, this->m_apiKey, ImGuiInputTextFlags_EnterReturnsTrue)) {
                        setApiKey(this->m_apiKey);
                        this->startAnalysisTask();

                        ImGui::CloseCurrentPopup();
                    }
                    ImGui::PopItemWidth();

                    View::confirmButtons("hex.builtin.common.okay"_lang, "hex.builtin.common.cancel"_lang,
                        [this] {
                            setApiKey(this->m_apiKey);
                            this->startAnalysisTask();
                            ImGui::CloseCurrentPopup();
                        },
                        [] {
                            ImGui::CloseCurrentPopup();
                        }
                    );
                } else {
                    ImGui::TextWrapped("mal.malcore.popup.upload.description"_lang);

                    ImGui::NewLine();

                    View::confirmButtons("hex.builtin.common.okay"_lang, "hex.builtin.common.cancel"_lang,
                        [this] {
                            this->startAnalysisTask();
                            ImGui::CloseCurrentPopup();
                        },
                        [] {
                            ImGui::CloseCurrentPopup();
                        }
                    );
                }

                ImGui::EndPopup();
            }
        }

        [[nodiscard]] bool isAvailable() const override {
            return this->m_analysisValid && View::isAvailable();
        }

    private:
        void startAnalysisTask() {
            this->m_analysisValid = false;

            for (const auto &highlight : this->m_highlightedAddresses)
                ImHexApi::HexEditor::removeBackgroundHighlight(highlight);
            for (const auto &tooltip : this->m_tooltips)
                ImHexApi::HexEditor::removeTooltip(tooltip);

            this->m_highlightedAddresses.clear();
            this->m_tooltips.clear();

            TaskManager::createTask("mal.malcore.analyzing"_lang, 0, [this](auto &) {
                auto provider = ImHexApi::Provider::get();
                auto uuid = mal::hlp::MalcoreApi::uploadProviderData(provider, { provider->getBaseAddress(), provider->getBaseAddress() + provider->getActualSize() }).get();

                if (!uuid.has_value()) {

                    return;
                }

                std::optional<nlohmann::json> status;
                while (true) {
                    status = mal::hlp::MalcoreApi::getAnalysisStatus(*uuid).get();

                    if (!status.has_value()) {

                        return;
                    }

                    if (mal::hlp::MalcoreApi::isAnalysisFinished(*status)) {
                        break;
                    }

                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    log::info("{}", status->dump(4));
                }

                if (status.has_value()) {
                    this->m_threatScore             = mal::hlp::MalcoreApi::getThreatScore(*status);
                    this->m_packerInformation       = mal::hlp::MalcoreApi::getPackerInformation(*status);
                    this->m_interestingStrings      = mal::hlp::MalcoreApi::getInterestingStrings(*status);
                    this->m_dynamicAnalysisResults  = mal::hlp::MalcoreApi::getDynamicAnalysisResult(*status);

                    this->m_analysisValid = true;
                    this->getWindowOpenState() = true;
                } else {

                }

                /*TaskManager::doLater([this]{
                    if (this->m_dynamicAnalysisResults.has_value()) {
                        for (const auto &result : this->m_dynamicAnalysisResults.value()) {
                            for (const auto &api : result.apis) {
                                this->m_highlightedAddresses.push_back(ImHexApi::HexEditor::addBackgroundHighlight({ api.pcValue, 8 }, 0x80FF0000));
                                this->m_tooltips.push_back(ImHexApi::HexEditor::addTooltip({ api.pcValue, 8 }, api.apiName, 0x80FF0000));
                            }
                        }
                    }
                });*/
            });
        }

        static void setApiKey(const std::string &key) {
            mal::hlp::MalcoreApi::setApiKey(key);
            ContentRegistry::Settings::write("mal.malcore.setting.general", "hex.malcore.setting.general.api_key", key);
        }

    private:
        std::string m_apiKey;

        std::atomic<bool> m_analysisValid = false;
        std::optional<mal::hlp::MalcoreApi::PackerInformation> m_packerInformation;
        std::optional<std::vector<std::string>> m_interestingStrings;
        std::optional<mal::hlp::MalcoreApi::ThreatScore> m_threatScore;
        std::optional<std::vector<mal::hlp::MalcoreApi::DynamicAnalysisResult>> m_dynamicAnalysisResults;

        std::vector<u32> m_highlightedAddresses, m_tooltips;
    };

}

IMHEX_PLUGIN_SETUP("Malcore", "Internet 2.0", "Plugin to integrate with Malcore services") {
    hex::log::debug("Using romfs: '{}'", romfs::name());
    for (auto &path : romfs::list("lang"))
        hex::ContentRegistry::Language::addLocalization(nlohmann::json::parse(romfs::get(path).string()));


    auto apiKey = ContentRegistry::Settings::read("mal.malcore.setting.general", "hex.malcore.setting.general.api_key", "");

    mal::hlp::MalcoreApi::setApiKey(apiKey);

    ContentRegistry::Interface::addMenuItem({ "hex.builtin.menu.help", "mal.malcore.menu.help.upload_to_malcore" }, 10000, Shortcut::None, [] {
        EventManager::post<RequestOpenPopup>("mal.malcore.popup.api_key"_lang);
    }, ImHexApi::Provider::isValid);

    ContentRegistry::Views::add<ViewMalcore>();

    EventManager::subscribe<RequestChangeTheme>([](const std::string &) {
        auto loadFromRomfs = [&](const std::string &path) {
            auto textureData = romfs::get(path);

            return ImGui::Texture(reinterpret_cast<const ImU8*>(textureData.data()), textureData.size());
        };

        s_bannerTexture = loadFromRomfs(hex::format("assets/malcore_banner{}.png", ThemeManager::getThemeImagePostfix()));

        if (!s_bannerTexture.isValid()) {
            log::error("Failed to load banner texture!");
        }
    });
}


