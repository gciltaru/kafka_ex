defmodule Kafka.Metadata.Test do
  use ExUnit.Case, async: true
  import Mock

  test "get_broker returns broker for topic and single partition" do
    response = TestHelper.generate_metadata_response(1,
      [%{:node_id => 0, :host => "localhost", :port => 9092},
       %{:node_id => 1, :host => "foo",       :port => 9092}],
      [%{:error_code => 0, :name => "test", partitions:
          [%{:error_code => 0, :id => 0, :leader => 0, :replicas => [0,1], :isrs => [0,1]},
           %{:error_code => 0, :id => 1, :leader => 0, :replicas => [0,1], :isrs => [0,1]}]},
       %{:error_code => 0, :name => "fnord", partitions:
          [%{:error_code => 0, :id => 0, :leader => 1, :replicas => [0,1], :isrs => [0,1]},
           %{:error_code => 0, :id => 1, :leader => 1, :replicas => [0,1], :isrs => [0,1]}]}])

    connection = %{:correlation_id => 1, :client_id => "client_id"}
    with_mock Kafka.Connection, [send_and_return_response: fn(_, _) -> {:ok, connection, response} end,
                                 connect: fn(_, _) -> {:ok, connection} end] do
      {:ok, metadata} = Kafka.Metadata.new([["localhost", 9092]], "foo")
      {:ok, broker, metadata} = Kafka.Metadata.get_broker(metadata, "fnord", 0)
      assert broker == %{:host => "foo", :port => 9092}
    end
  end

  test "get metadata for single node and topic" do
    response = TestHelper.generate_metadata_response(1,
      [%{:node_id => 0, :host => "localhost", :port => 9092}],
      [%{:error_code => 0, :name => "test", partitions:
          [%{:error_code => 0, :id => 0, :leader => 0, :replicas => [0], :isrs => [0]}]}])

    connection = %{:correlation_id => 1, :client_id => "client_id"}
    with_mock Kafka.Connection, [send_and_return_response: fn(_, _) -> {:ok, connection, response} end,
                                 connect: fn(_, _) -> {:ok, connection} end] do
      {:ok, %{:brokers => broker_map, :topics => topic_map, :timestamp => _}} =
        Kafka.Metadata.new(%{:correlation_id => 1}, "foo")
      assert broker_map == %{0 => %{:host => "localhost", :port => 9092}}
      assert topic_map  == %{"test" =>
        [error_code:  0, partitions:  %{0 => %{error_code:  0, isrs:  [0], leader:  0, replicas:  [0]}}]}
    end
  end

  test "get metadata for multiple nodes and topics" do
    response = TestHelper.generate_metadata_response(1,
      [%{:node_id => 0, :host => "localhost", :port => 9092},
       %{:node_id => 1, :host => "foo",       :port => 9092}],
      [%{:error_code => 0, :name => "test", partitions:
          [%{:error_code => 0, :id => 0, :leader => 0, :replicas => [0,1], :isrs => [0,1]},
           %{:error_code => 0, :id => 1, :leader => 0, :replicas => [0,1], :isrs => [0,1]}]},
       %{:error_code => 0, :name => "fnord", partitions:
          [%{:error_code => 0, :id => 0, :leader => 1, :replicas => [0,1], :isrs => [0,1]},
           %{:error_code => 0, :id => 1, :leader => 1, :replicas => [0,1], :isrs => [0,1]}]}])

    connection = %{:correlation_id => 1, :client_id => "client_id"}
    with_mock Kafka.Connection, [send_and_return_response: fn(_, _) -> {:ok, connection, response} end,
                                 connect: fn(_, _) -> {:ok, connection} end] do

      {:ok, %{:brokers => broker_map, :topics => topic_map, :timestamp => _}} =
        Kafka.Metadata.new(%{:correlation_id => 1}, "foo")
      assert broker_map == %{0 =>
        %{:host => "localhost", :port => 9092}, 1 => %{:host => "foo", :port => 9092}}
      assert topic_map  == %{"fnord" => [error_code: 0,
          partitions: %{0 => %{:error_code => 0, :isrs => [0, 1], :leader => 1, :replicas => [0, 1]},
                        1 => %{:error_code => 0, :isrs => [0, 1], :leader => 1, :replicas => [0, 1]}}],
        "test" => [error_code: 0,
          partitions: %{0 => %{:error_code => 0, :isrs => [0, 1], :leader => 0, :replicas => [0, 1]},
                        1 => %{:error_code => 0, :isrs => [0, 1], :leader => 0, :replicas => [0, 1]}}]}
    end
  end

  test "calling get_broker in < 5 minutes returns the same metadata" do
    response = TestHelper.generate_metadata_response(1,
      [%{:node_id => 0, :host => "localhost", :port => 9092}],
      [%{:error_code => 0, :name => "test", partitions:
          [%{:error_code => 0, :id => 0, :leader => 0, :replicas => [0], :isrs => [0]}]}])

    connection = %{:correlation_id => 1, :client_id => "client_id"}
    with_mock Kafka.Connection, [send_and_return_response: fn(_, _) -> {:ok, connection, response} end,
                                 connect: fn(_, _) -> {:ok, connection} end] do
      {:ok, metadata} = Kafka.Metadata.new(%{:correlation_id => 1}, "foo")
      :timer.sleep(1000)
      assert {:ok, %{host: "localhost", port: 9092}, metadata} == Kafka.Metadata.get_broker(metadata, "test", 0)
    end
  end

  test "calling get_broker in > 5 minutes returns new metadata" do
    response = TestHelper.generate_metadata_response(1,
      [%{:node_id => 0, :host => "localhost", :port => 9092}],
      [%{:error_code => 0, :name => "test", partitions:
          [%{:error_code => 0, :id => 0, :leader => 0, :replicas => [0], :isrs => [0]}]}])

    connection = %{:correlation_id => 1, :client_id => "client_id"}
    with_mock Kafka.Connection, [send_and_return_response: fn(_, _) -> {:ok, connection, response} end,
                                 connect: fn(_, _) -> {:ok, connection} end] do
      {:ok, metadata} = Kafka.Metadata.new(%{:correlation_id => 1}, "foo")
      {mega, secs, _} = :os.timestamp
      ts = mega * 1000000 + secs + 6 * 60
      with_mock Kafka.Helper, [get_timestamp: fn -> ts end] do
        assert {:ok, metadata} != Kafka.Metadata.get_broker(metadata, "foo", 0)
      end
    end
  end
end