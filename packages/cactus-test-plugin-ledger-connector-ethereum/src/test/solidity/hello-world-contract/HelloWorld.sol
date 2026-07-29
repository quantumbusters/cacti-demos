// *****************************************************************************
// IMPORTANT: If you update this code then make sure to recompile
// it and update the .json file as well so that they
// remain in sync for consistent test executions.
// With that said, there shouldn't be any reason to recompile this, like ever...
// *****************************************************************************

pragma solidity >=0.8.0;

/**
 * @title HelloWorld
 * @author Cacti Contributors
 * @notice A simple hello world contract
 */
contract HelloWorld {
  string private name = "CaptainCactus";

  /**
   * @notice Returns a hello world greeting
   */
  function sayHello () public pure returns (string memory) {
    return "Hello World!";
  }

  /**
   * @notice Gets the name
   */
  function getName() public view returns (string memory)
  {
      return name;
  }

  /**
   * @notice Sets the name
   * @param newName The new name to set
   */
  function setName(string memory newName) public
  {
      name = newName;
  }
}
