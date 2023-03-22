#pragma once

#include <hex/providers/provider.hpp>
#include <hex/helpers/http_requests.hpp>

#include <wolv/literals.hpp>

namespace mal::hlp {

    using namespace wolv::literals;

    class MalcoreApi {
    public:
        static auto uploadProviderData(hex::prv::Provider *provider, hex::Region region) {
            std::vector<u8> data;
            data.resize(std::min<size_t>(region.getSize(), s_uploadLimit));
            provider->read(region.getStartAddress(), data.data(), data.size());

            return std::async(std::launch::async, [data = std::move(data)]() mutable -> std::optional<std::string> {
                auto request = createRequest("POST", "/upload");
                auto response = request.uploadFile<std::string>(data, "filename1").get();

                if (!response.isSuccess())
                    return std::nullopt;

                try {
                    auto json = nlohmann::json::parse(response.getData());

                    return json["data"]["data"]["uuid"].get<std::string>();
                } catch (std::exception &e) {
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


        static void setApiKey(std::string apiKey) {
            s_apiKey = std::move(apiKey);
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