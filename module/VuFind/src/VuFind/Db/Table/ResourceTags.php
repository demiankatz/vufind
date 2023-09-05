<?php

/**
 * Table Definition for resource_tags
 *
 * PHP version 8
 *
 * Copyright (C) Villanova University 2010.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * @category VuFind
 * @package  Db_Table
 * @author   Demian Katz <demian.katz@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     https://vufind.org Main Site
 */

namespace VuFind\Db\Table;

use Laminas\Db\Adapter\Adapter;
use Laminas\Db\Sql\Expression;
use Laminas\Db\Sql\Select;
use VuFind\Db\Row\RowGateway;

use function count;
use function in_array;
use function is_array;

/**
 * Table Definition for resource_tags
 *
 * @category VuFind
 * @package  Db_Table
 * @author   Demian Katz <demian.katz@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     https://vufind.org Main Site
 */
class ResourceTags extends Gateway
{
    /**
     * Are tags case sensitive?
     *
     * @var bool
     */
    protected $caseSensitive;

    /**
     * Constructor
     *
     * @param Adapter       $adapter       Database adapter
     * @param PluginManager $tm            Table manager
     * @param array         $cfg           Laminas configuration
     * @param RowGateway    $rowObj        Row prototype object (null for default)
     * @param bool          $caseSensitive Are tags case sensitive?
     * @param string        $table         Name of database table to interface with
     */
    public function __construct(
        Adapter $adapter,
        PluginManager $tm,
        $cfg,
        ?RowGateway $rowObj = null,
        $caseSensitive = false,
        $table = 'resource_tags'
    ) {
        $this->caseSensitive = $caseSensitive;
        parent::__construct($adapter, $tm, $cfg, $rowObj, $table);
    }

    /**
     * Look up a row for the specified resource.
     *
     * @param string $resource ID of resource to link up
     * @param string $tag      ID of tag to link up
     * @param string $user     ID of user creating link (optional but recommended)
     * @param string $list     ID of list to link up (optional)
     * @param string $posted   Posted date (optional -- omit for current)
     *
     * @return void
     */
    public function createLink(
        $resource,
        $tag,
        $user = null,
        $list = null,
        $posted = null
    ) {
        $callback = function ($select) use ($resource, $tag, $user, $list) {
            $select->where->equalTo('resource_id', $resource)
                ->equalTo('tag_id', $tag);
            if (null !== $list) {
                $select->where->equalTo('list_id', $list);
            } else {
                $select->where->isNull('list_id');
            }
            if (null !== $user) {
                $select->where->equalTo('user_id', $user);
            } else {
                $select->where->isNull('user_id');
            }
        };
        $result = $this->select($callback)->current();

        // Only create row if it does not already exist:
        if (empty($result)) {
            $result = $this->createRow();
            $result->resource_id = $resource;
            $result->tag_id = $tag;
            if (null !== $list) {
                $result->list_id = $list;
            }
            if (null !== $user) {
                $result->user_id = $user;
            }
            if (null !== $posted) {
                $result->posted = $posted;
            }
            $result->save();
        }
    }

    /**
     * Check whether or not the specified tags are present in the table.
     *
     * @param array $ids IDs to check.
     *
     * @return array     Associative array with two keys: present and missing
     */
    public function checkForTags($ids)
    {
        // Set up return arrays:
        $retVal = ['present' => [], 'missing' => []];

        // Look up IDs in the table:
        $callback = function ($select) use ($ids) {
            $select->where->in('tag_id', $ids);
        };
        $results = $this->select($callback);

        // Record all IDs that are present:
        foreach ($results as $current) {
            $retVal['present'][] = $current->tag_id;
        }
        $retVal['present'] = array_unique($retVal['present']);

        // Detect missing IDs:
        foreach ($ids as $current) {
            if (!in_array($current, $retVal['present'])) {
                $retVal['missing'][] = $current;
            }
        }

        // Send back the results:
        return $retVal;
    }

    /**
     * Get resources associated with a particular tag.
     *
     * @param string $tag    Tag to match
     * @param string $userId ID of user owning favorite list
     * @param string $listId ID of list to retrieve (null for all favorites)
     *
     * @return \Laminas\Db\ResultSet\AbstractResultSet
     */
    public function getResourcesForTag($tag, $userId, $listId = null)
    {
        $callback = function ($select) use ($tag, $userId, $listId) {
            $select->columns(
                [
                    'resource_id' => new Expression(
                        'DISTINCT(?)',
                        ['resource_tags.resource_id'],
                        [Expression::TYPE_IDENTIFIER]
                    ), Select::SQL_STAR,
                ]
            );
            $select->join(
                ['t' => 'tags'],
                'resource_tags.tag_id = t.id',
                []
            );
            if ($this->caseSensitive) {
                $select->where->equalTo('t.tag', $tag);
            } else {
                $select->where->literal('lower(t.tag) = lower(?)', [$tag]);
            }
            $select->where->equalTo('resource_tags.user_id', $userId);
            if (null !== $listId) {
                $select->where->equalTo('resource_tags.list_id', $listId);
            }
        };

        return $this->select($callback);
    }

    /**
     * Get lists associated with a particular tag.
     *
     * @param string|array      $tag        Tag to match
     * @param null|string|array $listId     List ID to retrieve (null for all)
     * @param bool              $publicOnly Whether to return only public lists
     * @param bool              $andTags    Use AND operator when filtering by tag.
     *
     * @return \Laminas\Db\ResultSet\AbstractResultSet
     */
    public function getListsForTag(
        $tag,
        $listId = null,
        $publicOnly = true,
        $andTags = true
    ) {
        $tag = (array)$tag;
        $listId = $listId ? (array)$listId : null;

        $callback = function ($select) use (
            $tag,
            $listId,
            $publicOnly,
            $andTags
        ) {
            $select->columns(
                ['id' => new Expression('min(resource_tags.id)'), 'list_id']
            );

            $select->join(
                ['t' => 'tags'],
                'resource_tags.tag_id = t.id',
                []
            );
            $select->join(
                ['l' => 'user_list'],
                'resource_tags.list_id = l.id',
                []
            );

            // Discard tags assigned to a user resource.
            $select->where->isNull('resource_id');

            // Restrict to tags by list owner
            $select->where->and->equalTo(
                'resource_tags.user_id',
                new Expression('l.user_id')
            );

            if ($listId) {
                $select->where->and->in('resource_tags.list_id', $listId);
            }
            if ($publicOnly) {
                $select->where->and->equalTo('public', 1);
            }
            if ($tag) {
                if ($this->caseSensitive) {
                    $select->where->and->in('t.tag', $tag);
                } else {
                    $lowerTags = array_map(
                        function ($t) {
                            return new Expression(
                                'lower(?)',
                                [$t],
                                [Expression::TYPE_VALUE]
                            );
                        },
                        $tag
                    );
                    $select->where->and->in(
                        new Expression('lower(t.tag)'),
                        $lowerTags
                    );
                }
            }
            $select->group('resource_tags.list_id');

            if ($tag && $andTags) {
                // Use AND operator for tags
                $select->having->literal(
                    'count(distinct(resource_tags.tag_id)) = ?',
                    count(array_unique($tag))
                );
            }
            $select->order('resource_tags.list_id');
        };

        return $this->select($callback);
    }

    /**
     * Unlink rows for the specified resource.
     *
     * @param string|array $resource ID (or array of IDs) of resource(s) to
     * unlink (null for ALL matching resources)
     * @param string       $user     ID of user removing links
     * @param string       $list     ID of list to unlink (null for ALL matching
     * tags, 'none' for tags not in a list, true for tags only found in a list)
     * @param string|array $tag      ID or array of IDs of tag(s) to unlink (null
     * for ALL matching tags)
     *
     * @return void
     */
    public function destroyResourceLinks($resource, $user, $list = null, $tag = null)
    {
        $callback = function ($select) use ($resource, $user, $list, $tag) {
            $select->where->equalTo('user_id', $user);
            if (null !== $resource) {
                $select->where->in('resource_id', (array)$resource);
            }
            if (null !== $list) {
                if (true === $list) {
                    // special case -- if $list is set to boolean true, we
                    // want to only delete tags that are associated with lists.
                    $select->where->isNotNull('list_id');
                } elseif ('none' === $list) {
                    // special case -- if $list is set to the string "none", we
                    // want to delete tags that are not associated with lists.
                    $select->where->isNull('list_id');
                } else {
                    $select->where->equalTo('list_id', $list);
                }
            }
            if (null !== $tag) {
                if (is_array($tag)) {
                    $select->where->in('tag_id', $tag);
                } else {
                    $select->where->equalTo('tag_id', $tag);
                }
            }
        };
        $this->processDestroyLinks($callback);
    }

    /**
     * Unlink rows for the specified user list.
     *
     * @param string       $list ID of list to unlink
     * @param string       $user ID of user removing links
     * @param string|array $tag  ID or array of IDs of tag(s) to unlink (null
     * for ALL matching tags)
     *
     * @return void
     */
    public function destroyListLinks($list, $user, $tag = null)
    {
        $callback = function ($select) use ($user, $list, $tag) {
            $select->where->equalTo('user_id', $user);
            // retrieve tags assigned to a user list
            // and filter out user resource tags
            // (resource_id is NULL for list tags).
            $select->where->isNull('resource_id');
            $select->where->equalTo('list_id', $list);

            if (null !== $tag) {
                if (is_array($tag)) {
                    $select->where->in('tag_id', $tag);
                } else {
                    $select->where->equalTo('tag_id', $tag);
                }
            }
        };
        $this->processDestroyLinks($callback);
    }

    /**
     * Process link rows marked to be destroyed.
     *
     * @param Object $callback Callback function for selecting deleted rows.
     *
     * @return void
     */
    protected function processDestroyLinks($callback)
    {
        // Get a list of all tag IDs being deleted; we'll use these for
        // orphan-checking:
        $potentialOrphans = $this->select($callback);

        // Now delete the unwanted rows:
        $this->delete($callback);

        // Check for orphans:
        if (count($potentialOrphans) > 0) {
            $ids = [];
            foreach ($potentialOrphans as $current) {
                $ids[] = $current->tag_id;
            }
            $checkResults = $this->checkForTags(array_unique($ids));
            if (count($checkResults['missing']) > 0) {
                $tagTable = $this->getDbTable('Tags');
                $tagTable->deleteByIdArray($checkResults['missing']);
            }
        }
    }

    /**
     * Assign anonymous tags to the specified user ID.
     *
     * @param int $id User ID to own anonymous tags.
     *
     * @return void
     */
    public function assignAnonymousTags($id)
    {
        $callback = function ($select) {
            $select->where->isNull('user_id');
        };
        $this->update(['user_id' => $id], $callback);
    }

    /**
     * Given an array for sorting database results, make sure the tag field is
     * sorted in a case-insensitive fashion.
     *
     * @param array $order Order settings
     *
     * @return array
     */
    protected function formatTagOrder($order)
    {
        if (empty($order)) {
            return $order;
        }
        $newOrder = [];
        foreach ((array)$order as $current) {
            $newOrder[] = $current == 'tag'
                ? new Expression('lower(tag)') : $current;
        }
        return $newOrder;
    }

    /**
     * Get a list of duplicate rows (this sometimes happens after merging IDs,
     * for example after a Summon resource ID changes).
     *
     * @return mixed
     */
    public function getDuplicates()
    {
        $callback = function ($select) {
            $select->columns(
                [
                    'resource_id' => new Expression(
                        'MIN(?)',
                        ['resource_id'],
                        [Expression::TYPE_IDENTIFIER]
                    ),
                    'tag_id' => new Expression(
                        'MIN(?)',
                        ['tag_id'],
                        [Expression::TYPE_IDENTIFIER]
                    ),
                    'list_id' => new Expression(
                        'MIN(?)',
                        ['list_id'],
                        [Expression::TYPE_IDENTIFIER]
                    ),
                    'user_id' => new Expression(
                        'MIN(?)',
                        ['user_id'],
                        [Expression::TYPE_IDENTIFIER]
                    ),
                    'cnt' => new Expression(
                        'COUNT(?)',
                        ['resource_id'],
                        [Expression::TYPE_IDENTIFIER]
                    ),
                    'id' => new Expression(
                        'MIN(?)',
                        ['id'],
                        [Expression::TYPE_IDENTIFIER]
                    ),
                ]
            );
            $select->group(['resource_id', 'tag_id', 'list_id', 'user_id']);
            $select->having('COUNT(resource_id) > 1');
        };
        return $this->select($callback);
    }

    /**
     * Deduplicate rows (sometimes necessary after merging foreign key IDs).
     *
     * @return void
     */
    public function deduplicate()
    {
        foreach ($this->getDuplicates() as $dupe) {
            $callback = function ($select) use ($dupe) {
                // match on all relevant IDs in duplicate group
                $select->where(
                    [
                        'resource_id' => $dupe['resource_id'],
                        'tag_id' => $dupe['tag_id'],
                        'list_id' => $dupe['list_id'],
                        'user_id' => $dupe['user_id'],
                    ]
                );
                // getDuplicates returns the minimum id in the set, so we want to
                // delete all of the duplicates with a higher id value.
                $select->where->greaterThan('id', $dupe['id']);
            };
            $this->delete($callback);
        }
    }
}
