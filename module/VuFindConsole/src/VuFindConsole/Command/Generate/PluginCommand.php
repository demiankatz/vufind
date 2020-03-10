<?php
/**
 * Console command: Generate plugin.
 *
 * PHP version 7
 *
 * Copyright (C) Villanova University 2020.
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
 * @package  Console
 * @author   Demian Katz <demian.katz@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     https://vufind.org/wiki/development Wiki
 */
namespace VuFindConsole\Command\Generate;

use Interop\Container\ContainerInterface;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use VuFindConsole\Generator\GeneratorTools;

/**
 * Console command: Generate plugin.
 *
 * @category VuFind
 * @package  Console
 * @author   Demian Katz <demian.katz@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     https://vufind.org/wiki/development Wiki
 */
class PluginCommand extends AbstractCommand
{
    /**
     * The name of the command (the part after "public/index.php")
     *
     * @var string
     */
    protected static $defaultName = 'generate/plugin';

    /**
     * Top-level service container
     *
     * @var ContainerInterface
     */
    protected $container;

    /**
     * Constructor
     *
     * @param GeneratorTools     $tools     Generator tools
     * @param ContainerInterface $container Top-level service container
     * @param string|null        $name      The name of the command; passing null
     * means it must be set in configure()
     */
    public function __construct(GeneratorTools $tools, ContainerInterface $container,
        $name = null
    ) {
        $this->generatorTools = $tools;
        parent::__construct($tools, $name);
    }

    /**
     * Configure the command.
     *
     * @return void
     */
    protected function configure()
    {
        $this
            ->setDescription('Plugin generator')
            ->setHelp('Creates a new plugin class.')
            ->addArgument(
                'class_name',
                InputArgument::REQUIRED,
                'the name of the class you wish to create'
            )->addArgument(
                'factory',
                InputArgument::OPTIONAL,
                'an existing factory to use (omit to generate a new one)'
            );
    }

    /**
     * Run the command.
     *
     * @param InputInterface  $input  Input object
     * @param OutputInterface $output Output object
     *
     * @return int 0 for success
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $class = $input->getArgument('class_name');
        $factory = $input->getArgument('factory');
        try {
            $this->generatorTools->setOutputInterface($output);
            $this->generatorTools->createPlugin($this->container, $class, $factory);
        } catch (\Exception $e) {
            $output->writeln($e->getMessage());
            return 1;
        }
        return 0;
    }
}
