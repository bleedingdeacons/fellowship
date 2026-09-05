<?php

declare(strict_types=1);

namespace Fellowship\Tests\Support;

use wpdb;

/**
 * A $wpdb that records what it was asked and answers what it was told to.
 *
 * <b>Local rather than wp-mocks' Doubles\FakeWpdb, for one reason.</b>
 * That class is final and extends nothing, and Fellowship's repositories
 * type-hint the real `wpdb` — deliberately, since a repository handed
 * something that is not a database connection is a wiring fault worth
 * failing on. A stand-in therefore has to *be* a wpdb, which means
 * extending the minimal class the bootstrap declares. LifeLines keeps a
 * local double for a comparable reason.
 *
 * What it is for is asserting on the *SQL*, not on rows. The behaviour
 * that matters most in these repositories cannot be observed any other
 * way: `revoked_at IS NULL` is part of the lookup rather than a check a
 * caller makes afterwards, and the only place that fact is visible is the
 * statement itself.
 */
final class RecordingWpdb extends wpdb
{
    /** @var list<string> Every statement passed to a query method, in order. */
    public array $queries = [];

    /** @var list<array<string, mixed>> Rows the next read will answer with. */
    public array $results = [];

    public mixed $var = null;

    /** @var list<array{table: string, data: array<string, mixed>}> */
    public array $inserts = [];

    /** @var list<array{table: string, data: array<string, mixed>, where: array<string, mixed>}> */
    public array $updates = [];

    /** @var list<array{table: string, where: array<string, mixed>}> */
    public array $deletes = [];

    public mixed $insertResult = 1;

    public mixed $updateResult = 1;

    public mixed $deleteResult = 1;

    public mixed $queryResult = 0;

    public function __construct()
    {
        $this->prefix = 'wp_';
        $this->insert_id = 1;
    }

    public function get_results(string $query, mixed $output = null): array
    {
        $this->queries[] = $query;

        return $this->results;
    }

    public function get_row(string $query, mixed $output = null, int $y = 0): mixed
    {
        $this->queries[] = $query;

        return $this->results[0] ?? null;
    }

    public function get_var(string $query, int $x = 0, int $y = 0): mixed
    {
        $this->queries[] = $query;

        return $this->var;
    }

    public function query(string $query): mixed
    {
        $this->queries[] = $query;

        return $this->queryResult;
    }

    public function insert(string $table, array $data, mixed $formats = null): mixed
    {
        $this->inserts[] = ['table' => $table, 'data' => $data];

        return $this->insertResult;
    }

    public function update(string $table, array $data, array $where, mixed $f = null, mixed $wf = null): mixed
    {
        $this->updates[] = ['table' => $table, 'data' => $data, 'where' => $where];

        return $this->updateResult;
    }

    public function delete(string $table, array $where, mixed $formats = null): mixed
    {
        $this->deletes[] = ['table' => $table, 'where' => $where];

        return $this->deleteResult;
    }

    /** The most recent statement, which is what most assertions want. */
    public function lastQuery(): string
    {
        return $this->queries === [] ? '' : $this->queries[count($this->queries) - 1];
    }
}
