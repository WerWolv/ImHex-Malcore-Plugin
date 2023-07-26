#pragma once

#include <hex/helpers/http_requests.hpp>
#include <hex/providers/provider.hpp>

#include <wolv/literals.hpp>

namespace mal::hlp {

    using namespace wolv::literals;

    class MalcoreApi {
    public:
        struct PackerInformation {
            std::string name;
            u32 confidence = 0;
        };

        struct Signature {
            std::string title, description;
            nlohmann::json discovered;
        };

        struct ThreatScore {
            float score = 0.0F;
            std::vector<Signature> signatures;
        };

        struct Api {
            std::string apiName;
            u64 pcValue = 0x00;

            std::vector<std::string> arguments;
            std::string returnValue;
        };

        struct DynamicAnalysisResult {
            std::string hash;
            std::vector<Api> apis;
        };

        static auto uploadProviderData(hex::prv::Provider *provider, hex::Region region) {
            std::vector<u8> data;
            data.resize(std::min<size_t>(region.getSize(), s_uploadLimit));
            provider->read(region.getStartAddress(), data.data(), data.size());

            return std::async(std::launch::async, [data = std::move(data)]() mutable -> std::optional<std::string> {
                auto request = createRequest("POST", "/upload");
                auto response = request.uploadFile<std::string>(data, "filename1").get();

                if (!response.isSuccess()) {
                    hex::log::error("Failed to upload file to malcore: {}", response.getStatusCode());
                    return std::nullopt;
                }

                try {
                    auto json = nlohmann::json::parse(response.getData());

                    return json["data"]["data"]["uuid"].get<std::string>();
                } catch (std::exception &e) {
                    hex::log::error("Failed to get UUID: {}", e.what());
                    return std::nullopt;
                }
            });
        }

        static auto getAnalysisStatus(const std::string &uuid) {
            return std::async(std::launch::async, [uuid]() -> std::optional<nlohmann::json> {
                auto request = createRequest("POST", "/status");
                request.setBody("uuid=" + uuid);
                auto response = request.execute<std::string>().get();

                if (!response.isSuccess())
                    return std::nullopt;

                try {
                    return nlohmann::json::parse(response.getData());
                } catch (std::exception &e) {
                    return std::nullopt;
                }
            });
        }

        static bool isAnalysisFinished(const nlohmann::json &analysis) {
            return analysis["messages"][0]["type"].get<std::string>() == "success";
        }

        static std::optional<PackerInformation> getPackerInformation(const nlohmann::json &analysis) {
            try {
                auto &packerInformation = analysis["data"]["packer_information"][0];

                PackerInformation result;
                result.name = packerInformation["packer_name"].get<std::string>();

                auto confidenceString = packerInformation["percent"].get<std::string>();
                result.confidence = std::strtoul(confidenceString.c_str(), nullptr, 10);

                return result;
            } catch (nlohmann::json::exception &) {
                return std::nullopt;
            }
        }

        static std::optional<std::vector<std::string>> getInterestingStrings(const nlohmann::json &analysis) {
            try {
                auto &strings = analysis["data"]["interesting_strings"]["results"];

                std::vector<std::string> result;
                for (auto &string : strings)
                    result.push_back(string.get<std::string>());

                return result;
            } catch (nlohmann::json::exception &) {
                return std::nullopt;
            }
        }

        static std::optional<ThreatScore> getThreatScore(const nlohmann::json &analysis) {
            try {
                const auto &threatScore = analysis["data"]["threat_score"]["results"];

                ThreatScore result;
                result.score = std::strtof(threatScore["score"].get<std::string>().c_str(), nullptr);

                for (auto &signature : threatScore["signatures"]) {
                    const auto &info = signature["info"];
                    result.signatures.push_back({
                        info["title"].get<std::string>(),
                        info["description"].get<std::string>(),
                        signature["discovered"]
                    });
                }

                return result;
            } catch (nlohmann::json::exception &e) {
                hex::log::error("Failed to get threat score: {}", e.what());
                return std::nullopt;
            }
        }

        static std::optional<std::vector<DynamicAnalysisResult>> getDynamicAnalysisResult(const nlohmann::json &analysis) {
            try {
                auto &dynamicAnalysisList = analysis["data"]["dynamic_analysis"]["dynamic_analysis"];

                std::vector<DynamicAnalysisResult> results;

                for (const auto &dynamicAnalysis : dynamicAnalysisList) {
                    for (const auto &entryPoint : dynamicAnalysis["entry_points"]) {
                        DynamicAnalysisResult result;

                        result.hash = entryPoint["apihash"].get<std::string>();
                        for (const auto &api : entryPoint["apis"]) {
                            Api apiResult;
                            apiResult.apiName = api["api_name"].get<std::string>();
                            apiResult.pcValue = std::strtoull(api["pc"].get<std::string>().c_str(), nullptr, 16);

                            for (const auto &argument : api["args"])
                                apiResult.arguments.push_back(argument.get<std::string>());

                            if (api["ret_val"].is_string())
                                apiResult.returnValue = api["ret_val"].get<std::string>();

                            result.apis.emplace_back(std::move(apiResult));
                        }

                        results.emplace_back(std::move(result));
                    }
                }

                return results;
            } catch (nlohmann::json::exception &e) {
                hex::log::error("Failed to get dynamic analysis result: {}", e.what());
                return std::nullopt;
            }
        }


        static void setApiKey(std::string apiKey) {
            s_apiKey = std::move(apiKey);
        }

        static bool hasApiKey() {
            return !s_apiKey.empty();
        }

        static void setUploadLimit(size_t limit) {
            s_uploadLimit = limit;
        }

    private:
        static hex::HttpRequest createRequest(const std::string &method, const std::string &endpoint) {
            hex::HttpRequest request(method, ApiUrl + endpoint);
            request.addHeader("apiKey", MalcoreApi::s_apiKey);
            request.addHeader("X-No-Poll", "true");

            return request;
        }

    private:
        MalcoreApi() = default;
        ~MalcoreApi() = default;

        const static inline std::string ApiUrl = "https://api.malcore.io/api";

        static inline std::string s_apiKey;
        static inline u64 s_uploadLimit = 20_MiB;
    };

}