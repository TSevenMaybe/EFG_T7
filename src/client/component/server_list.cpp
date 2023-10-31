#include <std_include.hpp>
#include "loader/component_loader.hpp"
#include "server_list.hpp"

#include "game/game.hpp"

#include <utils/string.hpp>
#include <utils/concurrency.hpp>
#include <utils/hook.hpp>
#include <utils/io.hpp>

#include "network.hpp"
#include "scheduler.hpp"
#include <tuple>

namespace server_list
{
	namespace
	{
		utils::hook::detour lua_server_info_to_table_hook;

		struct state
		{
			game::netadr_t address{};
			bool requesting{ false };
			std::chrono::high_resolution_clock::time_point query_start{};
			callback callback{};
		};

		utils::concurrency::container<state> master_state;

		utils::concurrency::container<server_list> favorite_servers{};

		void handle_server_list_response(const game::netadr_t& target,
			const network::data_view& data, state& s)
		{
			if (!s.requesting || s.address != target)
			{
				return;
			}

			s.requesting = false;
			const auto callback = std::move(s.callback);

			std::optional<size_t> start{};

			for (size_t i = 0; i + 6 < data.size(); ++i)
			{
				if (data[i + 6] == '\\')
				{
					start.emplace(i);
					break;
				}
			}

			if (!start.has_value())
			{
				callback(true, {});
				return;
			}

			std::unordered_set<game::netadr_t> result{};

			for (auto i = start.value(); i + 6 < data.size(); i += 7)
			{
				if (data[i + 6] != '\\')
				{
					break;
				}

				game::netadr_t address{};
				address.type = game::NA_RAWIP;
				address.localNetID = game::NS_CLIENT1;
				memcpy(&address.ipv4.a, data.data() + i + 0, 4);
				memcpy(&address.port, data.data() + i + 4, 2);
				address.port = ntohs(address.port);

				result.emplace(address);
			}

			callback(true, result);
		}

		void lua_server_info_to_table_stub(game::hks::lua_State* state, game::ServerInfo server_info, int index)
		{
			lua_server_info_to_table_hook.invoke(state, server_info, index);

			if (state)
			{
				const auto bot_count = atoi(game::Info_ValueForKey(server_info.tags, "bots"));
				game::Lua_SetTableInt("botCount", bot_count, state);
			}
		}

		std::string get_favorite_servers_file_path()
		{
			return "t7efg_players/user/favorite_servers.txt";
		}

		void write_favorite_servers()
		{
			favorite_servers.access([](const std::unordered_set<game::netadr_t>& servers)
				{
					std::string servers_buffer{};
					for (const auto& itr : servers)
					{
						servers_buffer.append(utils::string::va("%i.%i.%i.%i:%hu\n", itr.ipv4.a, itr.ipv4.b, itr.ipv4.c, itr.ipv4.d, itr.port));
					}

					utils::io::write_file(get_favorite_servers_file_path(), servers_buffer);
				});
		}

		void read_favorite_servers()
		{
			const std::string path = get_favorite_servers_file_path();
			if (!utils::io::file_exists(path))
			{
				return;
			}

			favorite_servers.access([&path](std::unordered_set<game::netadr_t>& servers)
				{
					servers.clear();

					std::string data;
					if (utils::io::read_file(path, &data))
					{
						const auto srv = utils::string::split(data, '\n');
						for (const auto& server_address : srv)
						{
							auto server = network::address_from_string(server_address);
							servers.insert(server);
						}
					}
				});
		}
	}

	std::string get_master_server_file_path() //MASTER SERVER ADDRESS FROM master_server.txt
	{
		return "./master_server.txt";
	}

	std::pair<game::netadr_t, game::netadr_t> get_master_servers()
	{
		
		game::netadr_t address2 = network::address_from_string("master.ezz.lol:20810");
		game::netadr_t address1 = network::address_from_string("master.efg-en.net:20810");
		return std::make_pair(address1, address2);
	}
	/*
	void request_servers(callback callback)
	{
		master_state.access([&callback](state& s)
		{
		std::pair<game::netadr_t, game::netadr_t> addresses = get_master_servers();
		game::netadr_t addr1 = addresses.first;
		game::netadr_t addr2 = addresses.second;

		s.requesting = true;
		s.callback = std::move(callback);
		s.query_start = std::chrono::high_resolution_clock::now();
		s.address = addr1;

		bool validAddressesFound = (addr1.type != game::NA_BAD) || (addr2.type != game::NA_BAD);

		// Send the request for addr1
		if (addr1.type != game::NA_BAD)
		{
			try
			{
				printf("request sent 1");
				network::send(addr1, "getservers", utils::string::va("T7 %i full empty", PROTOCOL));
			}
			catch (const std::exception& e)
			{
				// Handle the exception, e.g., print an error message
				printf("Error in network::send for addr1: %s\n", e.what());
			}
		}

		// Send the request for addr2
		if (addr2.type != game::NA_BAD)
		{
			try
			{
				printf("request sent 2");
				network::send(addr2, "getservers", utils::string::va("T7 %i full empty", PROTOCOL));
			}
			catch (const std::exception& e)
			{
				// Handle the exception, e.g., print an error message
				printf("Error in network::send for addr2: %s\n", e.what());
			}
		}

		// ... Rest of your code ...

		if (!validAddressesFound)
		{
			// If no valid addresses were found, send the request for the default master server address
			printf("Default master Server\n");
			network::send(addr1, "getservers", utils::string::va("T7 %i full empty", PROTOCOL));
		}
		});
	}*/

	bool get_master_server(game::netadr_t& address)
	{

		const std::string path = get_master_server_file_path();
		if (utils::io::file_exists(path))
		{
			std::string data;
			if (utils::io::read_file(path, &data))
			{
				std::string master_server = data;
				address = network::address_from_string(master_server);
				return address.type != game::NA_BAD;
			}
		}

		address = network::address_from_string("master.efg-en.net:20810"); //DEFAULT MASTER SERVER ADDRESS FOR SERVER LIST
		//address = network::address_from_string("master.ezz.lol:20810"); //DEFAULT MASTER SERVER ADDRESS FOR SERVER LIST

		return address.type != game::NA_BAD;
	}

	void request_servers_2(callback callback)
	{
		master_state.access([&callback](state& s2)
		{
			game::netadr_t addr{};
			if (!get_master_server(addr))
			{
				return;
			}

			s2.requesting = true;
			s2.address = addr;
			s2.callback = std::move(callback);
			s2.query_start = std::chrono::high_resolution_clock::now();

			network::send(s2.address, "getservers", utils::string::va("T7 %i full empty", PROTOCOL));
		});
	}

	
	
	void request_servers(callback callback)
	{
		master_state.access([&callback](state& s)
			{
				game::netadr_t addr{};
				if (!get_master_server(addr))
				{
					return;
				}

				s.requesting = true;
				s.address = addr;
				s.callback = std::move(callback);
				s.query_start = std::chrono::high_resolution_clock::now();

				network::send(s.address, "getservers", utils::string::va("T7 %i full empty", PROTOCOL));
			});
	}
	

	std::string netadr_to_string(const game::netadr_t& adr)
	{
		// Extract the individual bytes from the netipv4_t structure
		uint8_t byte1 = adr.ipv4.a;
		uint8_t byte2 = adr.ipv4.b;
		uint8_t byte3 = adr.ipv4.c;
		uint8_t byte4 = adr.ipv4.d;

		// Convert the port to a string
		std::string portStr = std::to_string(adr.port);

		// Create the IP address string
		std::string ipStr = std::to_string(byte1) + "." +
			std::to_string(byte2) + "." +
			std::to_string(byte3) + "." +
			std::to_string(byte4);

		// Combine the IP address and port into a single string
		return ipStr + ":" + portStr;
	}
	/*
	void request_servers(callback callback)
	{
		master_state.access([&callback](state& s)
			{
				game::netadr_t addr{};
				if (!get_master_server(addr))
				{
					// Log an error message
					printf("Error: Failed to get the default master server address.\n");
					return;
				}

				s.requesting = true;
				s.callback = std::move(callback);
				s.query_start = std::chrono::high_resolution_clock::now();
				s.address = addr;

				bool validAddressesFound = false;  // Flag to track if any valid addresses were found

				const std::string path = get_master_server_file_path();
				if (utils::io::file_exists(path))
				{
					std::ifstream file(path);
					std::string server_address;

					while (std::getline(file, server_address))
					{
						auto server = network::address_from_string(server_address);

						if (server.type != game::NA_BAD)
						{
							// Create a copy of s for each server address
							state new_state = s;
							new_state.address = server;

							printf("Server address: %s\n", server_address.c_str());

							// Convert game::netadr_t to a string using your custom function
							//game::netadr_t new_state;
							std::string newAddressStr = netadr_to_string(new_state.address);
							printf("New_state address: %s\n", newAddressStr.c_str());

							try
							{
								network::send(new_state.address, "getservers", utils::string::va("T7 %i full empty", PROTOCOL));
								validAddressesFound = true;
							}
							catch (const std::exception& e)
							{
								// Handle the exception, e.g., print an error message
								printf("Error in network::send: %s\n", e.what());
							}
						}
						else
						{
							// Log an error message for an invalid server address
							printf("Error: Invalid server address - %s\n", server_address.c_str());
						}
					}
				}
				else
				{
					// Log an error message if the file doesn't exist
					printf("Error: The master_server.txt file does not exist.\n");
				}

				if (!validAddressesFound)
				{
					// If no valid addresses were found, send the request for the default master server address
					printf("Default master Server \n");
					network::send(addr, "getservers", utils::string::va("T7 %i full empty", PROTOCOL));
				}
			});
	}*/

	void add_favorite_server(game::netadr_t addr)
	{
		favorite_servers.access([&addr](std::unordered_set<game::netadr_t>& servers)
			{
				servers.insert(addr);
			});
		write_favorite_servers();
	}

	void remove_favorite_server(game::netadr_t addr)
	{
		favorite_servers.access([&addr](std::unordered_set<game::netadr_t>& servers)
			{
				for (auto it = servers.begin(); it != servers.end(); ++it)
				{
					if (network::are_addresses_equal(*it, addr))
					{
						servers.erase(it);
						break;
					}
				}
			});
		write_favorite_servers();
	}

	utils::concurrency::container<server_list>& get_favorite_servers()
	{
		return favorite_servers;
	}

	struct component final : client_component
	{
		void post_unpack() override
		{
			network::on("getServersResponse", [](const game::netadr_t& target, const network::data_view& data)
				{
					master_state.access([&](state& s)
						{
							handle_server_list_response(target, data, s);
						});
				});

			scheduler::loop([]
				{
					master_state.access([](state& s)
						{
							if (!s.requesting)
							{
								return;
							}

							const auto now = std::chrono::high_resolution_clock::now();
							if ((now - s.query_start) < 2s)
							{
								return;
							}

							s.requesting = false;
							s.callback(false, {});
							s.callback = {};
						});
				}, scheduler::async, 200ms);

			lua_server_info_to_table_hook.create(0x141F1FD10_g, lua_server_info_to_table_stub);

			scheduler::once([]
				{
					read_favorite_servers();
				}, scheduler::main);
		}

		void pre_destroy() override
		{
			master_state.access([](state& s)
				{
					s.requesting = false;
					s.callback = {};
				});
		}
	};
}

REGISTER_COMPONENT(server_list::component)
