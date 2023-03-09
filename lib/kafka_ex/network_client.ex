defmodule KafkaEx.NetworkClient do
  require Logger
  alias KafkaEx.New
  alias KafkaEx.Protocol.Metadata.Broker
  alias KafkaEx.Socket

  @moduledoc false
  @spec create_socket(binary, non_neg_integer, KafkaEx.ssl_options(), boolean) ::
          nil | Socket.t()
  def create_socket(host, port, ssl_options \\ [], use_ssl \\ false, sasl_options \\ []) do
    case Socket.create(
           format_host(host),
           port,
           build_socket_options(ssl_options),
           use_ssl
         ) do
      {:ok, socket} ->
        Logger.log(
          :debug,
          "Successfully connected to broker #{inspect(host)}:#{inspect(port)}"
        )

        if handle_auth(socket, sasl_options) do
          socket
        else
          nil
        end

        socket

      err ->
        Logger.log(
          :error,
          "Could not connect to broker #{inspect(host)}:#{inspect(port)} because of error #{inspect(err)}"
        )

        nil
    end
  end

  defp handle_auth(socket, sasl_options) do
    case sasl_options do
      {:sasl, mechanism, opts} ->
        resp = sasl_handshake(socket, String.upcase(Atom.to_string(mechanism)))

        if success(resp) do
          resp =
            sasl_authenticate(socket, Keyword.get(opts, :token_provider))

          if success(resp) do
            socket
          else
            nil
          end
        end

      _ ->
        nil
    end
  end

  defp sasl_handshake(socket, mechanism) do
    request = %{
      Kayrock.SaslHandshake.get_request_struct(1)
    | mechanism: mechanism,
      client_id: Config.client_id(),
      correlation_id: 0
    }

    :ok = Socket.setopts(socket, [:binary, {:packet, 4}, {:active, false}])

    resp = send_auth_request(socket, request)
  end

  defp send_auth_request(socket, request) do
    case Socket.send(socket, Kayrock.Request.serialize(request)) do
      :ok ->
        case Socket.recv(socket, 0, 25000) do
          {:ok, data} ->
            :ok = Socket.setopts(socket, [:binary, {:packet, 4}, {:active, true}])

            deserializer = Kayrock.Request.response_deserializer(request)
            {resp, _} = deserializer.(data)
            resp

          {:error, reason} ->
            Logger.log(
              :error,
              reason
            )
        end
    end
  end

  defp success(resp) do
    if resp.error_code == 0 do
      true
    else
      IO.inspect(resp)
      raise resp.error_message
    end
  end

  defp sasl_authenticate(socket, token_provider) do
    api_version = 0

    auth_bytes = "n,," <> <<1>> <> "auth=Bearer #{token_provider.token}" <> <<1>> <> <<1>>

    request = %{
      Kayrock.SaslAuthenticate.get_request_struct(api_version)
    | sasl_auth_bytes: auth_bytes,
      client_id: Config.client_id(),
      correlation_id: 1
    }

    :ok = Socket.setopts(socket, [:binary, {:packet, 4}, {:active, false}])

    resp = send_auth_request(socket, request)
  end


  @spec close_socket(nil | Socket.t()) :: :ok
  def close_socket(nil), do: :ok
  def close_socket(socket), do: Socket.close(socket)

  @spec send_async_request(Broker.t() | New.Broker.t(), iodata) ::
          :ok | {:error, :closed | :inet.posix()}
  def send_async_request(broker, data) do
    socket = broker.socket

    case Socket.send(socket, data) do
      :ok ->
        :ok

      {_, reason} ->
        Logger.log(
          :error,
          "Asynchronously sending data to broker #{inspect(broker.host)}:#{inspect(broker.port)} failed with #{inspect(reason)}"
        )

        reason
    end
  end

  @spec send_sync_request(Broker.t() | New.Broker.t(), iodata, timeout) ::
          iodata | {:error, any()}
  def send_sync_request(%{:socket => socket} = broker, data, timeout) do
    :ok = Socket.setopts(socket, [:binary, {:packet, 4}, {:active, false}])

    response =
      case Socket.send(socket, data) do
        :ok ->
          case Socket.recv(socket, 0, timeout) do
            {:ok, data} ->
              :ok =
                Socket.setopts(socket, [:binary, {:packet, 4}, {:active, true}])

              data

            {:error, reason} ->
              Logger.log(
                :error,
                "Receiving data from broker #{inspect(broker.host)}:#{inspect(broker.port)} failed with #{inspect(reason)}"
              )

              Socket.close(socket)

              {:error, reason}
          end

        {_, reason} ->
          Logger.log(
            :error,
            "Sending data to broker #{inspect(broker.host)}:#{inspect(broker.port)} failed with #{inspect(reason)}"
          )

          Socket.close(socket)

          {:error, reason}
      end

    response
  end

  def send_sync_request(nil, _, _) do
    {:error, :no_broker}
  end

  @spec format_host(binary) :: [char] | :inet.ip_address()
  def format_host(host) do
    case Regex.scan(~r/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/, host) do
      [match_data] = [[_, _, _, _, _]] ->
        match_data
        |> tl
        |> List.flatten()
        |> Enum.map(&String.to_integer/1)
        |> List.to_tuple()

      # to_char_list is deprecated from Elixir 1.3 onward
      _ ->
        apply(String, :to_char_list, [host])
    end
  end

  defp build_socket_options([]) do
    [:binary, {:packet, 4}]
  end

  defp build_socket_options(ssl_options) do
    build_socket_options([]) ++ ssl_options
  end
end
