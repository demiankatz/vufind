<?php
/**
 * Helper class for managing blueprint theme's high-level (body vs. sidebar) page
 * layout.
 *
 * PHP version 5
 *
 * Copyright (C) Villanova University 2011.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * @category VuFind2
 * @package  View_Helpers
 * @author   Demian Katz <demian.katz@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     http://vufind.org/wiki/vufind2:developer_manual Wiki
 */
namespace VuFind\View\Helper\Blueprint;

/**
 * Helper class for managing blueprint theme's high-level (body vs. sidebar) page
 * layout.
 *
 * @category VuFind2
 * @package  View_Helpers
 * @author   Demian Katz <demian.katz@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     http://vufind.org/wiki/vufind2:developer_manual Wiki
 */
class LayoutClass extends \Zend\View\Helper\AbstractHelper
{
    /**
     * Does the sidebar go on the left?
     *
     * @var bool
     */
    protected $left;

    /**
     * Constructor
     *
     * @param bool $left Does the sidebar go on the left?
     */
    public function __construct($left = false)
    {
        $this->left = $left;
    }

    /**
     * Helper to allow easily configurable page layout -- given a broad class
     * name, return appropriate CSS classes to lay out the page according to
     * the current configuration file settings.
     *
     * @param string $class Type of class to return ('mainbody' or 'sidebar')
     *
     * @return string       CSS classes to apply
     */
    public function __invoke($class)
    {
        switch ($class) {
        case 'mainbody':
            return $this->left ? 'span-18 push-5 last' : 'span-18';
        case 'sidebar':
            return $this->left ? 'span-5 pull-18 sidebarOnLeft' : 'span-5 last';
        default:
            return '';
        }
    }
}